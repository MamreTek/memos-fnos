// Package oauthbridge implements the private OAuth exchange for the planned
// fnOS adapter. It does not establish NAS identity or issue Memos sessions.
package oauthbridge

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	codeTTL   = 60 * time.Second
	tokenTTL  = 60 * time.Second
	maxActive = 1024
)

var (
	challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	verifierPattern  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

type ProtocolError string

func (e ProtocolError) Error() string { return string(e) }

const (
	InvalidClient  ProtocolError = "invalid_client"
	InvalidRequest ProtocolError = "invalid_request"
	InvalidGrant   ProtocolError = "invalid_grant"
	InvalidToken   ProtocolError = "invalid_token"
	ServerError    ProtocolError = "server_error"
)

// Principal must come from a verified stable-identity mapping. A raw UID,
// username, client header, or NAS admin flag must never be used as that mapping.
type Principal struct {
	Subject     string `json:"sub"`
	DisplayName string `json:"display_name"`
}

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
}

type Authorization struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type Exchange struct {
	ClientID     string
	ClientSecret string
	Code         string
	RedirectURI  string
	CodeVerifier string
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type grant struct {
	principal Principal
	redirect  string
	challenge string
	expires   time.Time
}

type bearer struct {
	principal Principal
	expires   time.Time
}

type Provider struct {
	mu         sync.Mutex
	clientID   string
	secretHash [32]byte
	redirects  map[string]bool
	codes      map[[32]byte]grant
	tokens     map[[32]byte]bearer
	now        func() time.Time
}

func safeText(value string, max int) bool {
	if value == "" || len(value) > max || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func New(config Config) (*Provider, error) {
	if !safeText(config.ClientID, 128) || !safeText(config.ClientSecret, 256) || len(config.ClientSecret) < 32 || len(config.RedirectURIs) == 0 || len(config.RedirectURIs) > 2 {
		return nil, errors.New("E_OAUTH_CONFIG")
	}
	p := &Provider{
		clientID: config.ClientID, secretHash: sha256.Sum256([]byte(config.ClientSecret)),
		redirects: make(map[string]bool), codes: make(map[[32]byte]grant),
		tokens: make(map[[32]byte]bearer), now: time.Now,
	}
	for _, target := range config.RedirectURIs {
		u, err := url.Parse(target)
		if err != nil || !safeText(target, 2048) || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || p.redirects[target] {
			return nil, errors.New("E_OAUTH_REDIRECT_CONFIG")
		}
		p.redirects[target] = true
	}
	return p, nil
}

func randomToken() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", ServerError
	}
	return base64.RawURLEncoding.EncodeToString(data[:]), nil
}

func (p *Provider) prune(now time.Time) {
	for key, item := range p.codes {
		if !now.Before(item.expires) {
			delete(p.codes, key)
		}
	}
	for key, item := range p.tokens {
		if !now.Before(item.expires) {
			delete(p.tokens, key)
		}
	}
}

// Authorize must only be called after trusted gateway authentication and stable
// subject validation. This package deliberately provides no public grant route.
// Browser-bound state validation belongs to the separate launch/callback layer.
func (p *Provider) Authorize(request Authorization, principal Principal) (string, error) {
	challenge, err := base64.RawURLEncoding.DecodeString(request.CodeChallenge)
	if request.ClientID != p.clientID || !p.redirects[request.RedirectURI] || request.ResponseType != "code" || request.CodeChallengeMethod != "S256" || !challengePattern.MatchString(request.CodeChallenge) || err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != request.CodeChallenge || !safeText(request.State, 4096) || !safeText(principal.Subject, 256) || !safeText(principal.DisplayName, 256) {
		return "", InvalidRequest
	}
	code, err := randomToken()
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.prune(now)
	if len(p.codes)+len(p.tokens) >= maxActive {
		return "", ServerError
	}
	key := sha256.Sum256([]byte(code))
	if _, collision := p.codes[key]; collision {
		return "", ServerError
	}
	p.codes[key] = grant{principal: principal, redirect: request.RedirectURI, challenge: request.CodeChallenge, expires: now.Add(codeTTL)}
	target, _ := url.Parse(request.RedirectURI)
	query := target.Query()
	query.Set("code", code)
	query.Set("state", request.State)
	target.RawQuery = query.Encode()
	return target.String(), nil
}

func (p *Provider) Exchange(request Exchange) (TokenResponse, error) {
	secretHash := sha256.Sum256([]byte(request.ClientSecret))
	if request.ClientID != p.clientID || len(request.ClientSecret) > 256 || subtle.ConstantTimeCompare(secretHash[:], p.secretHash[:]) != 1 {
		return TokenResponse{}, InvalidClient
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.prune(now)
	key := sha256.Sum256([]byte(request.Code))
	item, found := p.codes[key]
	if !found {
		return TokenResponse{}, InvalidGrant
	}
	// A client-authenticated exchange consumes the code even on bad PKCE or
	// redirect binding. It cannot be retried with different credentials.
	delete(p.codes, key)
	verifierHash := sha256.Sum256([]byte(request.CodeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(verifierHash[:])
	if !verifierPattern.MatchString(request.CodeVerifier) || request.RedirectURI != item.redirect || !p.redirects[request.RedirectURI] || subtle.ConstantTimeCompare([]byte(challenge), []byte(item.challenge)) != 1 {
		return TokenResponse{}, InvalidGrant
	}
	token, err := randomToken()
	if err != nil {
		return TokenResponse{}, err
	}
	tokenKey := sha256.Sum256([]byte(token))
	if _, collision := p.tokens[tokenKey]; collision {
		return TokenResponse{}, ServerError
	}
	p.tokens[tokenKey] = bearer{principal: item.principal, expires: now.Add(tokenTTL)}
	return TokenResponse{AccessToken: token, TokenType: "Bearer", ExpiresIn: int(tokenTTL.Seconds())}, nil
}

func (p *Provider) UserInfo(token string) (Principal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune(p.now())
	item, found := p.tokens[sha256.Sum256([]byte(token))]
	if !found {
		return Principal{}, InvalidToken
	}
	return item.principal, nil
}

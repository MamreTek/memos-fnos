// Package browserflow binds the authorization-code callback to a short-lived
// browser cookie. It does not authenticate a NAS identity or publish an HTTP
// route; the full gateway/proxy and browser handoff must enforce those boundaries.
package browserflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/cedarot/fn-apps/apps/memos/auth-bridge/internal/endpoint"
	"github.com/cedarot/fn-apps/apps/memos/auth-bridge/internal/memosclient"
)

const CookieName = "memos_fnos_flow"
const ttl = 5 * time.Minute
const maxPending = 1024

var (
	Invalid  = errors.New("E_LOGIN_STATE")
	Busy     = errors.New("E_LOGIN_CAPACITY")
	appPath  = regexp.MustCompile(`^/app/[a-z0-9]+(?:-[a-z0-9]+)*$`)
	id       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	provider = regexp.MustCompile(`^identity-providers/[A-Za-z0-9_-]{1,128}$`)
	opaque   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

type Config struct {
	PublicOrigin     string
	NASOrigin        string
	GatewayPrefix    string
	ClientID         string
	IdentityProvider string
}

type Started struct {
	Location string
	Cookie   *http.Cookie
}

type pending struct {
	cookieHash [32]byte
	verifier   string
	expires    time.Time
}

type Flow struct {
	mu       sync.Mutex
	items    map[[32]byte]pending
	now      func() time.Time
	nasAuth  string
	callback string
	clientID string
	provider string
	secure   bool
	memos    *memosclient.Client
}

func New(config Config, memos *memosclient.Client) (*Flow, error) {
	public, publicErr := endpoint.Origin(config.PublicOrigin)
	nas, nasErr := endpoint.Origin(config.NASOrigin)
	if publicErr != nil || nasErr != nil || !appPath.MatchString(config.GatewayPrefix) || !id.MatchString(config.ClientID) || !provider.MatchString(config.IdentityProvider) || memos == nil {
		return nil, errors.New("E_LOGIN_CONFIG")
	}
	if memos.CallbackURI() != public.String()+"/fnos-auth/callback" {
		return nil, errors.New("E_LOGIN_CONFIG")
	}
	return &Flow{
		items: make(map[[32]byte]pending), now: time.Now,
		nasAuth:  nas.String() + config.GatewayPrefix + "/authorize",
		callback: public.String() + "/fnos-auth/callback", secure: public.Scheme == "https",
		clientID: config.ClientID, provider: config.IdentityProvider, memos: memos,
	}, nil
}

func random() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", Busy
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (f *Flow) cookie(value string, expired bool) *http.Cookie {
	c := &http.Cookie{Name: CookieName, Value: value, Path: "/fnos-auth", HttpOnly: true, Secure: f.secure, SameSite: http.SameSiteLaxMode}
	if expired {
		c.MaxAge, c.Expires = -1, time.Unix(1, 0).UTC()
	} else {
		c.MaxAge, c.Expires = int(ttl.Seconds()), f.now().Add(ttl).UTC()
	}
	return c
}

func (f *Flow) prune(now time.Time) {
	for key, item := range f.items {
		if !now.Before(item.expires) {
			delete(f.items, key)
		}
	}
}

func (f *Flow) Begin() (Started, error) {
	state, err := random()
	if err != nil {
		return Started{}, err
	}
	binding, err := random()
	if err != nil {
		return Started{}, err
	}
	verifier, err := random()
	if err != nil {
		return Started{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	f.prune(now)
	if len(f.items) >= maxPending {
		return Started{}, Busy
	}
	key := sha256.Sum256([]byte(state))
	if _, collision := f.items[key]; collision {
		return Started{}, Busy
	}
	f.items[key] = pending{cookieHash: sha256.Sum256([]byte(binding)), verifier: verifier, expires: now.Add(ttl)}
	challenge := sha256.Sum256([]byte(verifier))
	target, _ := url.Parse(f.nasAuth)
	target.RawQuery = url.Values{
		"client_id": {f.clientID}, "redirect_uri": {f.callback}, "response_type": {"code"},
		"state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"},
	}.Encode()
	return Started{Location: target.String(), Cookie: f.cookie(binding, false)}, nil
}

// Complete must receive the unmodified callback query and all parsed browser
// cookies, so duplicate state/code/cookie values cannot be hidden by Get().
// The caller must not publish Session until its browser account-switch guard
// is installed. This component deliberately does not write cookies or HTML.
func (f *Flow) Complete(ctx context.Context, query url.Values, cookies []*http.Cookie) (memosclient.Session, *http.Cookie, error) {
	if len(query) != 2 || len(query["state"]) != 1 || len(query["code"]) != 1 || !opaque.MatchString(query.Get("state")) || !opaque.MatchString(query.Get("code")) {
		return memosclient.Session{}, nil, Invalid
	}
	binding := ""
	for _, cookie := range cookies {
		if cookie != nil && cookie.Name == CookieName {
			if binding != "" || !opaque.MatchString(cookie.Value) {
				return memosclient.Session{}, nil, Invalid
			}
			binding = cookie.Value
		}
	}
	if binding == "" {
		return memosclient.Session{}, nil, Invalid
	}
	f.mu.Lock()
	f.prune(f.now())
	key := sha256.Sum256([]byte(query.Get("state")))
	item, found := f.items[key]
	hash := sha256.Sum256([]byte(binding))
	if !found || subtle.ConstantTimeCompare(item.cookieHash[:], hash[:]) != 1 {
		f.mu.Unlock()
		return memosclient.Session{}, nil, Invalid
	}
	delete(f.items, key)
	f.mu.Unlock()
	// Consume the state before the network exchange. A failed exchange cannot
	// be retried with a different code or race a second native sign-in.
	session, err := f.memos.SSOSignIn(ctx, f.provider, query.Get("code"), f.callback, item.verifier)
	return session, f.cookie("", true), err
}

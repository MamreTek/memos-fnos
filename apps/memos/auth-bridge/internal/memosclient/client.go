// Package memosclient uses Memos' native Connect authentication service. It
// neither signs JWTs nor stores NAS passwords or administrator credentials.
package memosclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/cedarot/fn-apps/apps/memos/auth-bridge/internal/endpoint"
)

const service = "/memos.api.AuthService/"
const maxResponse = 1 << 20

var (
	Unavailable = errors.New("E_MEMOS_UNAVAILABLE")
	Rejected    = errors.New("E_MEMOS_REJECTED")
	Invalid     = errors.New("E_MEMOS_RESPONSE")
	resource    = regexp.MustCompile(`^users/[A-Za-z0-9_-]{1,128}$`)
	provider    = regexp.MustCompile(`^identity-providers/[A-Za-z0-9_-]{1,128}$`)
	pkce        = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	codePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

type User struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// Session stays on the server. Do not serialize tokens into a page or URL.
type Session struct {
	User          User         `json:"-"`
	AccessToken   string       `json:"-"`
	RefreshCookie *http.Cookie `json:"-"`
}

func (Session) String() string { return "[redacted Memos session]" }

type Client struct {
	origin   string
	callback string
	secure   bool
	http     *http.Client
}

func New(origin, publicOrigin string) (*Client, error) {
	upstream, err := endpoint.Origin(origin)
	if err != nil {
		return nil, err
	}
	public, err := endpoint.Origin(publicOrigin)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxIdleConns: 8, MaxIdleConnsPerHost: 8,
		DisableCompression: true,
	}
	return &Client{origin: upstream.String(), callback: public.String() + "/fnos-auth/callback", secure: public.Scheme == "https", http: &http.Client{
		Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) CallbackURI() string { return c.callback }

func credential(value string) bool {
	if len(value) == 0 || len(value) > 8192 {
		return false
	}
	for _, b := range []byte(value) {
		if b <= 32 || b >= 127 || b == ';' || b == ',' || b == '"' || b == '\\' {
			return false
		}
	}
	return true
}

func validUser(user User) bool {
	return resource.MatchString(user.Name) && user.Username != "" && len(user.Username) <= 256 && (user.Role == "USER" || user.Role == "ADMIN")
}

func (c *Client) call(ctx context.Context, method string, payload any, token, refresh string, result any) ([]*http.Cookie, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, Invalid
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+service+method, bytes.NewReader(body))
	if err != nil {
		return nil, Invalid
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Connect-Protocol-Version", "1")
	// This is configured deployment context, never a caller's forwarded header.
	proto := "http"
	if c.secure {
		proto = "https"
	}
	r.Header.Set("X-Forwarded-Proto", proto)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if refresh != "" {
		r.AddCookie(&http.Cookie{Name: "memos_refresh", Value: refresh})
	}
	response, err := c.http.Do(r)
	if err != nil {
		return nil, Unavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, Rejected
	}
	if response.StatusCode != http.StatusOK {
		return nil, Unavailable
	}
	typeName, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || typeName != "application/json" || response.Header.Get("Content-Encoding") != "" {
		return nil, Invalid
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || len(data) > maxResponse || json.Unmarshal(data, result) != nil {
		return nil, Invalid
	}
	return response.Cookies(), nil
}

func (c *Client) session(ctx context.Context, method string, payload any, refresh string) (Session, error) {
	var body struct {
		AccessToken string `json:"accessToken"`
	}
	cookies, err := c.call(ctx, method, payload, "", refresh, &body)
	if err != nil {
		return Session{}, err
	}
	if !credential(body.AccessToken) {
		return Session{}, Invalid
	}
	var cookie *http.Cookie
	for _, candidate := range cookies {
		if candidate.Name != "memos_refresh" {
			// Do not forward unrelated upstream cookies into the browser.
			continue
		}
		if cookie != nil || candidate.Valid() != nil || !credential(candidate.Value) || candidate.Domain != "" || candidate.Path != "/" || !candidate.HttpOnly || candidate.SameSite != http.SameSiteLaxMode || candidate.Secure != c.secure || candidate.MaxAge < 0 || !candidate.Expires.After(time.Now()) {
			return Session{}, Invalid
		}
		copy := *candidate
		cookie = &copy
	}
	if cookie == nil {
		return Session{}, Invalid
	}
	// Ask Memos to verify its own token and resolve its current user. Never
	// trust an unverified JWT payload or a submitted display name as identity.
	user, err := c.CurrentUser(ctx, body.AccessToken)
	if err != nil {
		return Session{}, err
	}
	return Session{User: user, AccessToken: body.AccessToken, RefreshCookie: cookie}, nil
}

func (c *Client) SSOSignIn(ctx context.Context, identityProvider, code, redirectURI, verifier string) (Session, error) {
	if !provider.MatchString(identityProvider) || !codePattern.MatchString(code) || !pkce.MatchString(verifier) {
		return Session{}, Invalid
	}
	// The callback always comes from the browser-flow configuration, not a
	// request parameter. The provider checks that exact registered URL too.
	if redirectURI != c.callback {
		return Session{}, Invalid
	}
	return c.session(ctx, "SignIn", map[string]any{"ssoCredentials": map[string]string{
		"identityProvider": identityProvider, "code": code, "redirectUri": redirectURI, "codeVerifier": verifier,
	}}, "")
}

func (c *Client) CurrentUser(ctx context.Context, token string) (User, error) {
	if !credential(token) {
		return User{}, Invalid
	}
	var body struct {
		User User `json:"user"`
	}
	if _, err := c.call(ctx, "GetCurrentUser", struct{}{}, token, "", &body); err != nil {
		return User{}, err
	}
	if !validUser(body.User) {
		return User{}, Invalid
	}
	return body.User, nil
}

func (c *Client) Refresh(ctx context.Context, refresh string) (Session, error) {
	if !credential(refresh) {
		return Session{}, Invalid
	}
	return c.session(ctx, "RefreshToken", struct{}{}, refresh)
}

func (c *Client) SignOut(ctx context.Context, token, refresh string) error {
	if !credential(token) || !credential(refresh) {
		return Invalid
	}
	var body struct{}
	_, err := c.call(ctx, "SignOut", struct{}{}, token, refresh, &body)
	return err
}

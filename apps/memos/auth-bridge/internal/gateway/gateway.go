// Package gateway accepts fnOS identity only over a dedicated Unix listener.
// The caller must supply a verified account-lifecycle resolver; there is no
// implicit mapping from a reusable NAS UID or username to a Memos subject.
package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cedarot/fn-apps/apps/memos/auth-bridge/internal/endpoint"
	"github.com/cedarot/fn-apps/apps/memos/auth-bridge/internal/oauthbridge"
)

type listenerKey struct{}

// ConnContext must be installed on the HTTP server that owns the dedicated
// Unix socket. A handler accidentally mounted on TCP still refuses identity.
func ConnContext(ctx context.Context, connection net.Conn) context.Context {
	if _, ok := connection.LocalAddr().(*net.UnixAddr); ok {
		return context.WithValue(ctx, listenerKey{}, true)
	}
	return ctx
}

type Identity struct {
	UID      string `json:"-"`
	Username string `json:"-"`
	IsAdmin  bool   `json:"-"`
}

func (Identity) String() string { return "[redacted NAS identity]" }

// Resolver must distinguish deletion/recreation even when UID and name match.
// Returning an error prevents authorization; the gateway has no fallback.
type Resolver func(context.Context, Identity) (oauthbridge.Principal, error)

type Config struct {
	Prefix       string
	PublicOrigin string
	ClientID     string
	Provider     *oauthbridge.Provider
	Resolve      Resolver
}

type Handler struct {
	prefix   string
	login    string
	callback string
	clientID string
	provider *oauthbridge.Provider
	resolve  Resolver
}

var prefixPattern = regexp.MustCompile(`^/app/[a-z0-9]+(?:-[a-z0-9]+)*$`)
var uidPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,9})$`)
var opaquePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var clientPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func New(config Config) (*Handler, error) {
	public, err := endpoint.Origin(config.PublicOrigin)
	if err != nil || !prefixPattern.MatchString(config.Prefix) || !clientPattern.MatchString(config.ClientID) || config.Provider == nil || config.Resolve == nil {
		return nil, errors.New("E_GATEWAY_CONFIG")
	}
	return &Handler{
		prefix: config.Prefix, login: public.String() + "/fnos-auth/login",
		callback: public.String() + "/fnos-auth/callback", clientID: config.ClientID,
		provider: config.Provider, resolve: config.Resolve,
	}, nil
}

func identity(headers http.Header) (Identity, bool) {
	read := func(name string) (string, bool) {
		values := headers.Values(name)
		return strings.Join(values, ""), len(values) == 1
	}
	uid, uidOK := read("X-Trim-Userid")
	username, nameOK := read("X-Trim-Username")
	admin, adminOK := read("X-Trim-Isadmin")
	_, numberErr := strconv.ParseUint(uid, 10, 32)
	if !uidOK || !nameOK || !adminOK || !uidPattern.MatchString(uid) || numberErr != nil || username == "" || len(username) > 256 || !utf8.ValidString(username) || strings.TrimSpace(username) != username || (admin != "true" && admin != "false") {
		return Identity{}, false
	}
	for _, c := range username {
		if unicode.IsControl(c) {
			return Identity{}, false
		}
	}
	return Identity{UID: uid, Username: username, IsAdmin: admin == "true"}, true
}

func failure(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(code + "\n"))
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if trusted, _ := r.Context().Value(listenerKey{}).(bool); !trusted {
		failure(w, http.StatusForbidden, "E_GATEWAY_LISTENER")
		return
	}
	if r.URL.RawPath != "" || (r.URL.Path != h.prefix && r.URL.Path != h.prefix+"/authorize") {
		failure(w, http.StatusNotFound, "E_GATEWAY_ROUTE")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		failure(w, http.StatusMethodNotAllowed, "E_GATEWAY_METHOD")
		return
	}
	user, ok := identity(r.Header)
	if !ok {
		failure(w, http.StatusForbidden, "E_GATEWAY_IDENTITY")
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.URL.RawQuery) > 4096 {
		failure(w, http.StatusBadRequest, "E_GATEWAY_REQUEST")
		return
	}
	if r.URL.Path == h.prefix {
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			failure(w, http.StatusBadRequest, "E_GATEWAY_REQUEST")
			return
		}
		w.Header().Set("Location", h.login)
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	allowed := []string{"client_id", "redirect_uri", "response_type", "state", "code_challenge", "code_challenge_method"}
	valid := err == nil && len(query) == len(allowed)
	for _, name := range allowed {
		valid = valid && len(query[name]) == 1
	}
	if !valid || query.Get("client_id") != h.clientID || query.Get("redirect_uri") != h.callback || query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || !opaquePattern.MatchString(query.Get("state")) || !opaquePattern.MatchString(query.Get("code_challenge")) {
		failure(w, http.StatusBadRequest, "E_GATEWAY_REQUEST")
		return
	}
	principal, err := h.resolve(r.Context(), user)
	if err != nil {
		failure(w, http.StatusServiceUnavailable, "E_IDENTITY_LIFECYCLE")
		return
	}
	target, err := h.provider.Authorize(oauthbridge.Authorization{
		ClientID: query.Get("client_id"), RedirectURI: query.Get("redirect_uri"), ResponseType: query.Get("response_type"),
		State: query.Get("state"), CodeChallenge: query.Get("code_challenge"), CodeChallengeMethod: query.Get("code_challenge_method"),
	}, principal)
	if err != nil {
		failure(w, http.StatusBadRequest, "E_GATEWAY_AUTHORIZATION")
		return
	}
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusSeeOther)
}

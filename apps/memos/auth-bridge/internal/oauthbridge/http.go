package oauthbridge

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func fail(w http.ResponseWriter, status int, code ProtocolError) {
	if code == InvalidClient {
		w.Header().Set("WWW-Authenticate", `Basic realm="memos-fnos"`)
	}
	if code == InvalidToken {
		w.Header().Set("WWW-Authenticate", `Bearer realm="memos-fnos"`)
	}
	reply(w, status, map[string]string{"error": string(code)})
}

// PrivateHandler exposes only token exchange and userinfo. The future server
// must mount it on the private Docker listener, never on TCP 5230 or the gateway.
// Client-supplied X-Trim-* headers cannot create an authorization grant here.
func (p *Provider) PrivateHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				fail(w, http.StatusMethodNotAllowed, InvalidRequest)
				return
			}
			p.serveToken(w, r)
		case "/oauth/userinfo":
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				fail(w, http.StatusMethodNotAllowed, InvalidRequest)
				return
			}
			p.serveUserInfo(w, r)
		default:
			fail(w, http.StatusNotFound, InvalidRequest)
		}
	})
}

func (p *Provider) serveToken(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		fail(w, http.StatusBadRequest, InvalidRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, InvalidRequest)
		return
	}
	allowed := map[string]bool{"grant_type": true, "code": true, "redirect_uri": true, "code_verifier": true, "client_id": true, "client_secret": true}
	for key, values := range r.PostForm {
		if !allowed[key] || len(values) != 1 {
			fail(w, http.StatusBadRequest, InvalidRequest)
			return
		}
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		fail(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	clientID, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	authorization := r.Header.Values("Authorization")
	if len(authorization) > 0 {
		_, hasID := r.PostForm["client_id"]
		_, hasSecret := r.PostForm["client_secret"]
		if len(authorization) != 1 || hasID || hasSecret {
			fail(w, http.StatusBadRequest, InvalidRequest)
			return
		}
		encodedID, encodedSecret, ok := r.BasicAuth()
		var idErr, secretErr error
		clientID, idErr = url.QueryUnescape(encodedID)
		secret, secretErr = url.QueryUnescape(encodedSecret)
		if !ok || idErr != nil || secretErr != nil {
			fail(w, http.StatusUnauthorized, InvalidClient)
			return
		}
	}
	result, err := p.Exchange(Exchange{ClientID: clientID, ClientSecret: secret, Code: r.PostForm.Get("code"), RedirectURI: r.PostForm.Get("redirect_uri"), CodeVerifier: r.PostForm.Get("code_verifier")})
	if err != nil {
		code := err.(ProtocolError)
		status := http.StatusBadRequest
		if code == InvalidClient {
			status = http.StatusUnauthorized
		} else if code == ServerError {
			status = http.StatusServiceUnavailable
		}
		fail(w, status, code)
		return
	}
	reply(w, http.StatusOK, result)
}

func (p *Provider) serveUserInfo(w http.ResponseWriter, r *http.Request) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || r.URL.RawQuery != "" {
		fail(w, http.StatusUnauthorized, InvalidToken)
		return
	}
	parts := strings.Split(values[0], " ")
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || !challengePattern.MatchString(parts[1]) {
		fail(w, http.StatusUnauthorized, InvalidToken)
		return
	}
	principal, err := p.UserInfo(parts[1])
	if err != nil {
		fail(w, http.StatusUnauthorized, InvalidToken)
		return
	}
	reply(w, http.StatusOK, principal)
}

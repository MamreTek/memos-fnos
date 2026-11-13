// Package endpoint validates configured service origins. Request Host and
// forwarding headers are never used to discover an authentication target.
package endpoint

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

func Origin(value string) (*url.URL, error) {
	fail := errors.New("E_ORIGIN_CONFIG")
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, "\\%") {
		return nil, fail
	}
	for _, c := range value {
		if unicode.IsSpace(c) || unicode.IsControl(c) || c > 127 {
			return nil, fail
		}
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(value, "?#") {
		return nil, fail
	}
	if port := u.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return nil, fail
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, fail
	}
	u.Host = strings.ToLower(u.Host)
	u.Path, u.RawPath = "", ""
	return u, nil
}

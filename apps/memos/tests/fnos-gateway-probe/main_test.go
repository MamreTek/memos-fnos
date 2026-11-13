package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func request(headers map[string][]string, method, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	for k, values := range headers {
		for _, v := range values {
			r.Header.Add(k, v)
		}
	}
	w := httptest.NewRecorder()
	gatewayHandler(bytes.Repeat([]byte{3}, 32), &authChecks{}).ServeHTTP(w, r)
	return w
}

func identity(uid, username string) map[string][]string {
	return map[string][]string{"X-Trim-Userid": {uid}, "X-Trim-Username": {username}, "X-Trim-Isadmin": {"false"}}
}

func TestGatewayRejectsMissingAmbiguousOrInvalidIdentity(t *testing.T) {
	for _, field := range []string{"X-Trim-Userid", "X-Trim-Username", "X-Trim-Isadmin"} {
		for _, values := range [][]string{nil, {""}, {"1000", "1001"}, {"bad\nheader"}} {
			h := identity("1000", "private-test-name")
			h[field] = values
			w := request(h, "GET", prefix)
			if w.Code != 401 || strings.Contains(w.Body.String(), "private-test-name") {
				t.Fatal("invalid identity accepted or leaked")
			}
		}
	}
	for _, uid := range []string{"-1", " 1000", "01", "1000,1001", "100000000000000000000"} {
		if request(identity(uid, "name"), "GET", prefix).Code != 401 {
			t.Fatalf("accepted UID %q", uid)
		}
	}
}

func TestFixedRoutesAndNoSecretReflection(t *testing.T) {
	for _, path := range []string{"/", prefix + "/healthz", prefix + "/../private", prefix + "?code=secret"} {
		w := request(identity("1000", "name"), "GET", path)
		if w.Code == 200 || strings.Contains(w.Body.String(), "secret") {
			t.Fatal("invalid route accepted or query reflected")
		}
	}
	if request(identity("1000", "name"), "POST", prefix).Code != 400 {
		t.Fatal("accepted mutation")
	}
}

func TestFingerprintsAllowComparisonsWithoutReturningIdentity(t *testing.T) {
	decode := func(uid, name string) map[string]any {
		w := request(identity(uid, name), "GET", prefix)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("valid gateway request rejected or cached")
		}
		if strings.Contains(w.Body.String(), name) || strings.Contains(w.Body.String(), uid) {
			t.Fatal("raw identity leaked")
		}
		var v map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	a, renamed, b := decode("123456789", "private-alice"), decode("123456789", "private-renamed"), decode("987654321", "private-bob")
	if a["uid_fingerprint"] != renamed["uid_fingerprint"] || a["username_fingerprint"] == renamed["username_fingerprint"] {
		t.Fatal("rename not detectable")
	}
	if a["uid_fingerprint"] == b["uid_fingerprint"] {
		t.Fatal("different users collided")
	}
	if a["memos_sso_implemented"] != false || a["is_admin"] != false {
		t.Fatal("probe overstates capability")
	}
	if a["probe_version"] != "0.0.2" || a["installation_fingerprint"] != fingerprint(bytes.Repeat([]byte{3}, 32), "installation", "0.0.1") {
		t.Fatal("probe upgrade changed its stable installation fingerprint")
	}
	if fingerprint([]byte("other-install"), "uid", "123456789") == a["uid_fingerprint"] {
		t.Fatal("fingerprints link across installations")
	}
}

func TestPersistentPrivateKeyAndInvalidStatePreserved(t *testing.T) {
	dir := t.TempDir()
	a, err := loadKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadKey(dir)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("key changed after restart")
	}
	path := filepath.Join(dir, "fingerprint.key")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKey(dir); err == nil {
		t.Fatal("insecure key accepted")
	}
	if data, _ := os.ReadFile(path); !bytes.Equal(a, data) {
		t.Fatal("invalid key overwritten")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKey(dir); err == nil {
		t.Fatal("symlink accepted")
	}
}

package endpoint

import "testing"

func TestOriginContract(t *testing.T) {
	for input, expected := range map[string]string{
		"http://localhost:5230":  "http://localhost:5230",
		"https://Memos.Example/": "https://memos.example",
		"http://[::1]:5230/":     "http://[::1]:5230",
	} {
		origin, err := Origin(input)
		if err != nil || origin.String() != expected {
			t.Fatalf("valid configured origin rejected: %q", input)
		}
	}
	for _, input := range []string{
		"", "//memos.example", "ftp://memos.example", "https:memos.example",
		"https://user:secret@memos.example", "https://memos.example/path", "https://memos.example//",
		"https://memos.example?", "https://memos.example#", "https://memos.example?q=1",
		"https://memos.example/#fragment", "https://memos.example\\evil", "https://memos.example/%2f",
		"https://memos.example:", "https://memos.example:0", "https://memos.example:65536", "https://memos.example:port",
		" https://memos.example", "https://memos.example\r\n", "https://memos.例子", "http://[fe80::1%25eth0]",
	} {
		if _, err := Origin(input); err == nil {
			t.Fatalf("unsafe configured origin accepted: %q", input)
		}
	}
}

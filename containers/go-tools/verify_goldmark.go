// Verify the URL-escaping contract fixed by GO-2026-5320 without network traffic.
package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/yuin/goldmark"
)

func main() {
	cases := []struct{ input, want string }{
		{`[click](&#106;avascript:alert(1))`, `<p><a href="">click</a></p>`},
		{`<javascript:alert(document.domain)>`, `<p><a href="">javascript:alert(document.domain)</a></p>`},
		{`![alt](javascript:alert(document.domain))`, `<p><img src="" alt="alt"></p>`},
		{`[safe](https://example.test/path)`, `<p><a href="https://example.test/path">safe</a></p>`},
	}
	for _, test := range cases {
		var output bytes.Buffer
		if err := goldmark.Convert([]byte(test.input), &output); err != nil {
			panic(err)
		}
		if got := strings.TrimSpace(output.String()); got != test.want {
			panic(fmt.Sprintf("Goldmark URL safety mismatch: got %q; want %q", got, test.want))
		}
	}
	fmt.Println("Goldmark escaped-link, autolink, image and benign-link fixtures passed")
}

package manifest

import (
	"strings"
	"testing"
)

func TestVerifyBundle(t *testing.T) {
	r := newRekorFixture(t)
	b := &Bundle{Statement: r.f.statement, Signature: r.f.sig, Manifest: r.f.gz, RekorEntry: r.resp}
	pins := Pins{Signing: &r.f.key.PublicKey, Rekor: &r.rk.key.PublicKey}
	tr, err := VerifyBundle(b, "ami-0123456789abcdef0", pins)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Statement.AMIID != "ami-0123456789abcdef0" || tr.Rekor.TreeSize != 13 || tr.Index == nil {
		t.Fatalf("%+v", tr)
	}
	cases := map[string]func() (*Bundle, string, Pins){
		"other AMI": func() (*Bundle, string, Pins) { return b, "ami-0aaaaaaaaaaaaaaaa", pins },
		"no rekor pin": func() (*Bundle, string, Pins) {
			return b, "ami-0123456789abcdef0", Pins{Signing: pins.Signing}
		},
		"other rekor key": func() (*Bundle, string, Pins) {
			return b, "ami-0123456789abcdef0", Pins{Signing: pins.Signing, Rekor: &newFakeRekor(t).key.PublicKey}
		},
		"swapped manifest": func() (*Bundle, string, Pins) {
			c := *b
			c.Manifest = gzipBytes(t, []byte(`{"entries":[]}`))
			return &c, "ami-0123456789abcdef0", pins
		},
		"missing rekor entry": func() (*Bundle, string, Pins) {
			c := *b
			c.RekorEntry = nil
			return &c, "ami-0123456789abcdef0", pins
		},
	}
	for name, f := range cases {
		bb, ami, p := f()
		if _, err := VerifyBundle(bb, ami, p); err == nil {
			t.Errorf("%s: accepted", name)
		} else if testing.Verbose() {
			t.Logf("%s: %v", name, strings.SplitN(err.Error(), "\n", 2)[0])
		}
	}
}

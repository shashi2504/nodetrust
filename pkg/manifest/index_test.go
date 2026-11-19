package manifest

import "testing"

func TestIndexWhitespaceAlias(t *testing.T) {
	raw := []byte(`{"entries":[
		{"path":"/usr/lib/x/script (dev).tmpl","type":"file","sha256":"aa"},
		{"path":"/usr/lib/x/a b","type":"file","sha256":"bb"},
		{"path":"/usr/lib/x/a_b","type":"file","sha256":"cc"}]}`)
	idx, err := Index(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := idx["/usr/lib/x/script_(dev).tmpl"]; !ok || e.SHA256 != "aa" || e.Path != "/usr/lib/x/script (dev).tmpl" {
		t.Fatalf("alias: %+v %v", e, ok)
	}
	// A real file with the underscored name wins over the alias.
	if idx["/usr/lib/x/a_b"].SHA256 != "cc" {
		t.Fatalf("real file lost: %+v", idx["/usr/lib/x/a_b"])
	}
	if _, err := Index([]byte(`{"entries":[{"path":"/a","type":"file"},{"path":"/a","type":"file"}]}`)); err == nil {
		t.Fatal("duplicate accepted")
	}
}

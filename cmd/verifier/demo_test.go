package main

import "testing"

// The demo is also a test: every result it prints must be the expected one.
func TestDemo(t *testing.T) {
	if code := demo([]string{"-repo", "../.."}); code != 0 {
		t.Fatalf("demo exit %d", code)
	}
}

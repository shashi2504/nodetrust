package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"nodetrust/pkg/nodetrust"
)

// nodetrustCheck verifies the NodeTrust objects of a cluster (the output of
// "kubectl get nodetrusts -o json", on stdin) against the pinned public
// key: what the trust controller will do (step 4.7).
func nodetrustCheck(args []string) (code int) {
	defer func() { // readFile panics with a failure for a missing file
		if r := recover(); r != nil {
			f, ok := r.(failure)
			if !ok {
				panic(r)
			}
			code = fail(f)
		}
	}()
	fs := flag.NewFlagSet("nodetrust-check", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "PEM public key that NodeTrust updates must be signed with")
	maxAge := fs.Duration("max-age", 5*time.Minute, "an update older than this fails (0: no limit)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	pub, err := nodetrust.ParsePublicKey(readFile(*pubPath))
	if err != nil {
		return fail(err)
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fail(err)
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				Signed *nodetrust.Signed `json:"signed"`
				Tier   string            `json:"tier"`
				Score  float64           `json:"score"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return fail(fmt.Errorf("stdin: %w", err))
	}
	if len(list.Items) == 0 {
		return fail(fmt.Errorf("no NodeTrust objects"))
	}
	bad := 0
	now := time.Now()
	for _, it := range list.Items {
		st, err := nodetrust.Check(pub, it.Status.Signed, it.Metadata.Name, 0, now, *maxAge)
		if err != nil {
			fmt.Printf("FAIL %s %v\n", it.Metadata.Name, err)
			bad++
			continue
		}
		note := ""
		if st.Tier != it.Status.Tier || st.Score != it.Status.Score {
			note = fmt.Sprintf(" (the unsigned copy says %s %g)", it.Status.Tier, it.Status.Score)
		}
		fmt.Printf("OK %s seq=%d issued %s ago: %s %g critical=%t unattested=%t state=%s reboots=%d files=%d findings=%d%s\n",
			it.Metadata.Name, st.Seq, now.Sub(st.IssuedAt).Round(time.Second), st.Tier, st.Score, st.Critical,
			st.Unattested, st.State, st.Reboots, len(st.Files), len(st.Findings), note)
	}
	if bad > 0 {
		return 1
	}
	return 0
}

// Command verifier runs on a dedicated instance outside the cluster. It
// challenges agents, checks quotes and IMA logs against signed reference
// manifests, scores each node and writes signed NodeTrust updates.
// The attestation loop is implemented in Phase 4.
//
// Subcommands available now:
//
//	verifier verify-manifest -public-key K -statement S -signature G -manifest M -ami AMI \
//	    [-rekor-entry E -rekor-key R]
//
// checks a signed reference manifest (Phase 2) exactly as the verifier will
// before trusting it, including its Rekor transparency log entry when given.
//
//	verifier check-ima <the verify-manifest flags, Rekor required> \
//	    -policy P -snapshot S [-baseline B] [-show N]
//
// checks a node's IMA measurements (a snapshot from ima_snapshot.py) against
// that manifest and the runtime file policy (Phase 2, step 2.4).
//
//	verifier enroll-challenge | enroll-finish | check-quote
//
// enrollment by credential activation and quote checks (Phase 3, step 3.2).
//
//	verifier boot-reference -event-log L -ami AMI -firmware-why TEXT -out P [-base P0]
//	verifier check-boot <the verify-manifest flags, Rekor required> \
//	    -boot-policy P -event-log L -pcrs pcrs.txt -root-volume VOL
//
// boot event log checks (Phase 4, step 4.1).
//
//	verifier serve [-config /etc/nodetrust/verifier/config.json] [-once]
//
// the verifier service (Phase 4, step 4.2): enrolls workers from allowed
// AMIs and checks a quote from each one every interval.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"nodetrust/internal/version"
	"nodetrust/pkg/imapolicy"
	"nodetrust/pkg/manifest"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "verify-manifest":
			os.Exit(verifyManifest(os.Args[2:]))
		case "check-ima":
			os.Exit(checkIMA(os.Args[2:]))
		case "enroll-challenge":
			os.Exit(enrollChallenge(os.Args[2:]))
		case "enroll-finish":
			os.Exit(enrollFinish(os.Args[2:]))
		case "check-quote":
			os.Exit(checkQuote(os.Args[2:]))
		case "attest-node":
			os.Exit(attestNode(os.Args[2:]))
		case "boot-reference":
			os.Exit(bootReference(os.Args[2:]))
		case "check-boot":
			os.Exit(checkBoot(os.Args[2:]))
		case "serve":
			os.Exit(serve(os.Args[2:]))
		case "nodetrust-check":
			os.Exit(nodetrustCheck(os.Args[2:]))
		case "demo":
			os.Exit(demo(os.Args[2:]))
		}
	}

	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String("verifier"))
		return
	}
	fmt.Fprintln(os.Stderr, "usage: verifier serve|demo|nodetrust-check|verify-manifest|check-ima|enroll-challenge|enroll-finish|check-quote|attest-node|boot-reference|check-boot")
	os.Exit(2)
}

// trustFlags are the inputs needed to trust a manifest.
type trustFlags struct {
	pub, statement, signature, manifest, ami, rekorEntry, rekorKey *string
}

func addTrustFlags(fs *flag.FlagSet) trustFlags {
	return trustFlags{
		pub:        fs.String("public-key", "", "pinned signing public key (PEM)"),
		statement:  fs.String("statement", "", "statement.json"),
		signature:  fs.String("signature", "", "statement.sig (base64 DER)"),
		manifest:   fs.String("manifest", "", "manifest.json.gz"),
		ami:        fs.String("ami", "", "AMI the manifest must be for"),
		rekorEntry: fs.String("rekor-entry", "", "saved Rekor entry (rekor-entry.json)"),
		rekorKey:   fs.String("rekor-key", "", "pinned Rekor log public key (PEM)"),
	}
}

type failure string

func (f failure) Error() string { return string(f) }

func readFile(p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		panic(failure(err.Error()))
	}
	return b
}

// loadTrusted verifies the chain signature -> statement -> AMI -> manifest
// (-> Rekor entry when requireRekor or when given) and returns the manifest
// JSON. Lines describing what passed are printed as it goes.
func loadTrusted(f trustFlags, requireRekor bool) (raw []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			fe, ok := r.(failure)
			if !ok {
				panic(r)
			}
			err = fe
		}
	}()
	if *f.pub == "" || *f.statement == "" || *f.signature == "" || *f.manifest == "" || *f.ami == "" {
		return nil, failure("-public-key, -statement, -signature, -manifest and -ami are required")
	}
	if (*f.rekorEntry == "") != (*f.rekorKey == "") {
		return nil, failure("-rekor-entry and -rekor-key go together")
	}
	if requireRekor && *f.rekorEntry == "" {
		return nil, failure("-rekor-entry and -rekor-key are required")
	}

	pub, err := manifest.ParsePublicKeyPEM(readFile(*f.pub))
	if err != nil {
		return nil, err
	}
	stBytes, sigBytes := readFile(*f.statement), readFile(*f.signature)
	s, err := manifest.VerifyStatement(stBytes, sigBytes, pub)
	if err != nil {
		return nil, err
	}
	if s.AMIID != *f.ami {
		return nil, fmt.Errorf("statement is for %s, expected %s", s.AMIID, *f.ami)
	}
	raw, err = s.CheckManifestGz(readFile(*f.manifest))
	if err != nil {
		return nil, err
	}
	fmt.Printf("OK signature valid (key %s, signed %s)\n", s.KeyID, s.SignedAt)
	if *f.rekorEntry != "" {
		rk, err := manifest.ParsePublicKeyPEM(readFile(*f.rekorKey))
		if err != nil {
			return nil, fmt.Errorf("rekor key: %w", err)
		}
		uuid, e, err := manifest.ParseRekorResponse(readFile(*f.rekorEntry))
		if err != nil {
			return nil, err
		}
		res, err := manifest.VerifyRekor(uuid, e, stBytes, sigBytes, pub, rk)
		if err != nil {
			return nil, err
		}
		fmt.Printf("OK rekor entry %d logged %s (inclusion proof to tree size %d, checkpoint signed)\n",
			res.LogIndex, res.IntegratedTime.Format("2006-01-02T15:04:05Z"), res.TreeSize)
	}
	fmt.Printf("OK manifest for %s / %s in %s, %d bytes, entries_sha256 %s\n",
		s.AMIID, s.SnapshotID, s.Region, len(raw), s.EntriesSHA256)
	return raw, nil
}

func verifyManifest(args []string) int {
	fs := flag.NewFlagSet("verify-manifest", flag.ContinueOnError)
	tf := addTrustFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if _, err := loadTrusted(tf, false); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL", err)
		return 1
	}
	return 0
}

func checkIMA(args []string) int {
	fs := flag.NewFlagSet("check-ima", flag.ContinueOnError)
	tf := addTrustFlags(fs)
	policyPath := fs.String("policy", "", "runtime file policy (JSON)")
	snapPath := fs.String("snapshot", "", "IMA snapshot from ima_snapshot.py (.tsv or .tsv.gz)")
	basePath := fs.String("baseline", "", "earlier snapshot of the same node; only new measurements are checked")
	show := fs.Int("show", 40, "how many paths to list per failing class")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" || *snapPath == "" {
		fmt.Fprintln(os.Stderr, "check-ima: -policy and -snapshot are required")
		return 2
	}

	raw, err := loadTrusted(tf, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL", err)
		return 1
	}
	idx, err := manifest.Index(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL", err)
		return 1
	}
	pb, err := os.ReadFile(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL", err)
		return 1
	}
	pol, err := imapolicy.LoadPolicy(pb)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL", err)
		return 1
	}
	snap, err := imapolicy.ReadSnapshot(*snapPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL", err)
		return 1
	}
	// The snapshot must come from a log that replayed to the node's PCR 10.
	if snap.Meta["pcr10_match"] != "true" {
		fmt.Fprintf(os.Stderr, "FAIL snapshot %s: IMA log did not replay to PCR 10 (pcr10_match=%q)\n",
			*snapPath, snap.Meta["pcr10_match"])
		return 1
	}
	if snap.Meta["ami"] != "" && snap.Meta["ami"] != *tf.ami {
		fmt.Fprintf(os.Stderr, "FAIL snapshot is from %s, manifest is for %s\n", snap.Meta["ami"], *tf.ami)
		return 1
	}
	fmt.Printf("OK snapshot %s: %s attested entries replay to PCR 10 (%s bank)\n",
		*snapPath, snap.Meta["entries_attested"], snap.Meta["bank"])

	ms := snap.Measurements
	scope := "all attested measurements"
	if *basePath != "" {
		base, err := imapolicy.ReadSnapshot(*basePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "FAIL", err)
			return 1
		}
		ms = imapolicy.Without(ms, base.Measurements)
		scope = "measurements new since " + *basePath
	}

	r := imapolicy.Classify(ms, idx, pol)
	fmt.Printf("\n%s: %d distinct (path, hash) pairs\n", scope, len(ms))
	for _, c := range imapolicy.Classes {
		fmt.Printf("  %-10s %d\n", c, r.Counts[c])
	}

	// Which rules were used, so the policy can be reviewed.
	ruleUse := map[string]int{}
	for _, it := range r.Items {
		if it.Rule != "" {
			ruleUse[it.Class+" "+it.Rule]++
		}
	}
	if len(ruleUse) > 0 {
		fmt.Println("\nrules used:")
		for _, rl := range append(pol.Mutable, pol.Runtime...) {
			for _, c := range []string{imapolicy.Changed, imapolicy.Runtime} {
				if n := ruleUse[c+" "+rl.Pattern]; n > 0 {
					fmt.Printf("  %-8s %5d  %s\n", c, n, rl.Pattern)
				}
			}
		}
	}

	for _, c := range []string{imapolicy.Violation, imapolicy.Mismatch, imapolicy.Unknown} {
		if r.Counts[c] == 0 {
			continue
		}
		fmt.Printf("\n%s:\n", strings.ToUpper(c))
		n := 0
		for _, it := range r.Items {
			if it.Class != c {
				continue
			}
			if n == *show {
				fmt.Printf("  ... %d more\n", r.Counts[c]-n)
				break
			}
			fmt.Printf("  %-64s  x%-3d %s\n", it.SHA256, it.Count, it.Path)
			n++
		}
	}

	if r.Pass {
		fmt.Println("\nRESULT pass (no mismatch, no unknown)")
		return 0
	}
	fmt.Printf("\nRESULT fail (%d mismatch, %d unknown)\n", r.Counts[imapolicy.Mismatch], r.Counts[imapolicy.Unknown])
	return 1
}

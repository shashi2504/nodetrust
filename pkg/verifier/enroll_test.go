package verifier

import (
	"testing"
	"time"

	"nodetrust/pkg/protocol"
)

func TestFinishExpired(t *testing.T) {
	p := &Pending{Secret: []byte("s"), Created: time.Now().Add(-ChallengeTTL - time.Second)}
	if _, err := Finish(p, &protocol.ChallengeResponse{Version: protocol.Version, Secret: []byte("s")}, time.Now()); err == nil {
		t.Fatal("expired challenge accepted")
	}
}

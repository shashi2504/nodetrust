package verifier

import (
	"testing"
	"time"

	"nodetrust/pkg/trust"
)

func TestIntervalFor(t *testing.T) {
	now := t0.Add(time.Hour)
	d := &Daemon{Interval: 60 * time.Second, Now: func() time.Time { return now }}
	d.Load()
	set := func(f func(*Track)) {
		tr := NewTrack("i-1")
		tr.Seen, tr.Unattested = true, false
		f(tr)
		d.tracks["i-1"] = tr
	}
	for name, c := range map[string]struct {
		f    func(*Track)
		want time.Duration
	}{
		"healthy":         {func(*Track) {}, 60 * time.Second},
		"warning":         {func(t *Track) { t.Tier = trust.Warning }, 30 * time.Second},
		"degraded":        {func(t *Track) { t.Tier = trust.Degraded }, 15 * time.Second},
		"critical":        {func(t *Track) { t.Critical = true }, 15 * time.Second},
		"unattested":      {func(t *Track) { t.Unattested = true }, 15 * time.Second},
		"rebooted 5m ago": {func(t *Track) { t.LastChange = now.Add(-5 * time.Minute) }, 15 * time.Second},
		"changed 20m ago": {func(t *Track) { t.LastChange = now.Add(-20 * time.Minute) }, 60 * time.Second},
	} {
		set(c.f)
		if got := d.IntervalFor("i-1"); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
	delete(d.tracks, "i-1")
	if got := d.IntervalFor("i-1"); got != 15*time.Second {
		t.Errorf("new node: %s", got)
	}
	d.Interval = 10 * time.Second
	if got := d.IntervalFor("i-1"); got != minInterval {
		t.Errorf("floor: %s", got)
	}
}

func TestClaim(t *testing.T) {
	d := &Daemon{}
	d.Load()
	now := t0
	if !d.claim("i-1", now) {
		t.Fatal("a new node is due at once")
	}
	if d.claim("i-1", now) {
		t.Fatal("claimed twice while busy")
	}
	d.busy["i-1"], d.due["i-1"] = false, now.Add(time.Minute)
	if d.claim("i-1", now.Add(10*time.Second)) {
		t.Fatal("claimed before due")
	}
	// A hint after the last cycle brings it forward, but not within hintGap.
	d.hinted["i-1"] = now.Add(2 * time.Second)
	if d.claim("i-1", now.Add(3*time.Second)) {
		t.Fatal("hinted cycle within hintGap")
	}
	if !d.claim("i-1", now.Add(6*time.Second)) {
		t.Fatal("hinted cycle not claimed")
	}
	// The same hint does not trigger again.
	d.busy["i-1"] = false
	if d.claim("i-1", now.Add(20*time.Second)) {
		t.Fatal("old hint claimed again")
	}
}

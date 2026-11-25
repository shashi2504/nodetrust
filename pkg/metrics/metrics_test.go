package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTextFormat(t *testing.T) {
	r := New()
	r.Counter("x_total", "events")
	r.Histogram("d_seconds", "durations", []float64{1, 0.1})
	r.Inc("x_total", Labels{"node": "i-a", "type": `a"b`})
	r.Add("x_total", Labels{"node": "i-a", "type": `a"b`}, 2)
	r.Touch("x_total", Labels{"node": "i-b", "type": "c"})
	r.Add("x_total", nil, -1) // ignored: counters only go up
	r.Observe("d_seconds", Labels{"node": "i-a"}, 0.05)
	r.Observe("d_seconds", Labels{"node": "i-a"}, 0.5)
	r.Observe("d_seconds", Labels{"node": "i-a"}, 5)
	r.Collect(func(w *Writer) {
		w.Gauge("g", "a gauge", Labels{"node": "i-a"}, 72.5)
		w.Gauge("g", "a gauge", Labels{"node": "i-b"}, 100)
		w.Gauge("h", "plain", nil, 1)
	})
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	want := `# HELP d_seconds durations
# TYPE d_seconds histogram
d_seconds_bucket{node="i-a",le="0.1"} 1
d_seconds_bucket{node="i-a",le="1"} 2
d_seconds_bucket{node="i-a",le="+Inf"} 3
d_seconds_sum{node="i-a"} 5.55
d_seconds_count{node="i-a"} 3
# HELP x_total events
# TYPE x_total counter
x_total{node="i-a",type="a\"b"} 3
x_total{node="i-b",type="c"} 0
# HELP g a gauge
# TYPE g gauge
g{node="i-a"} 72.5
g{node="i-b"} 100
# HELP h plain
# TYPE h gauge
h 1
`
	if got := rec.Body.String(); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatal(rec.Header())
	}
}

// Package metrics is a small Prometheus text-format exporter, standard
// library only (the Prometheus client library cannot be fetched in this
// build environment). It has counters and histograms that code updates as
// things happen, and collectors that report gauges from current state when
// /metrics is read.
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Labels are a metric's label pairs.
type Labels map[string]string

// key renders labels in a fixed order, as they appear in the output.
func (l Labels) key() string {
	if len(l) == 0 {
		return ""
	}
	ks := make([]string, 0, len(l))
	for k := range l {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b strings.Builder
	for i, k := range ks {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(escape(l[k]))
		b.WriteByte('"')
	}
	return b.String()
}

func escape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func num(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

type family struct {
	name, help, kind string
	buckets          []float64
	values           map[string]float64 // counters: label key -> value
	hist             map[string]*histogram
}

type histogram struct {
	counts []uint64 // per bucket, not cumulative
	count  uint64
	sum    float64
}

// Registry holds the metrics of one program.
type Registry struct {
	mu         sync.Mutex
	families   map[string]*family
	collectors []func(*Writer)
}

// New returns an empty registry.
func New() *Registry { return &Registry{families: map[string]*family{}} }

// Counter declares a counter (call once per name).
func (r *Registry) Counter(name, help string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.families[name] = &family{name: name, help: help, kind: "counter", values: map[string]float64{}}
}

// Histogram declares a histogram with the given upper bounds.
func (r *Registry) Histogram(name, help string, buckets []float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := append([]float64(nil), buckets...)
	sort.Float64s(b)
	r.families[name] = &family{name: name, help: help, kind: "histogram", buckets: b, hist: map[string]*histogram{}}
}

// Add adds d (at least 0) to a counter.
func (r *Registry) Add(name string, l Labels, d float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.families[name]
	if f == nil || f.kind != "counter" || d < 0 {
		return
	}
	f.values[l.key()] += d
}

// Inc adds 1 to a counter.
func (r *Registry) Inc(name string, l Labels) { r.Add(name, l, 1) }

// Touch makes a counter series exist at 0, so a rule can see it before
// the first event.
func (r *Registry) Touch(name string, l Labels) { r.Add(name, l, 0) }

// Observe records one value in a histogram.
func (r *Registry) Observe(name string, l Labels, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.families[name]
	if f == nil || f.kind != "histogram" {
		return
	}
	k := l.key()
	h := f.hist[k]
	if h == nil {
		h = &histogram{counts: make([]uint64, len(f.buckets))}
		f.hist[k] = h
	}
	for i, b := range f.buckets {
		if v <= b {
			h.counts[i]++
			break
		}
	}
	h.count++
	h.sum += v
}

// Collect adds a function that writes gauges from current state at every
// scrape.
func (r *Registry) Collect(f func(*Writer)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors = append(r.collectors, f)
}

// Writer is what a collector writes gauges to.
type Writer struct {
	w        io.Writer
	declared map[string]bool
}

// Gauge writes one gauge sample; the HELP and TYPE lines are written
// before the first sample of each name.
func (w *Writer) Gauge(name, help string, l Labels, v float64) {
	if !w.declared[name] {
		w.declared[name] = true
		fmt.Fprintf(w.w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	}
	if k := l.key(); k != "" {
		fmt.Fprintf(w.w, "%s{%s} %s\n", name, k, num(v))
	} else {
		fmt.Fprintf(w.w, "%s %s\n", name, num(v))
	}
}

// Write writes every metric in the Prometheus text format.
func (r *Registry) Write(out io.Writer) {
	r.mu.Lock()
	names := make([]string, 0, len(r.families))
	for n := range r.families {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f := r.families[n]
		fmt.Fprintf(out, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, f.kind)
		switch f.kind {
		case "counter":
			for _, k := range sortedKeys(f.values) {
				writeSample(out, f.name, k, "", f.values[k])
			}
		case "histogram":
			keys := make([]string, 0, len(f.hist))
			for k := range f.hist {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				h := f.hist[k]
				var cum uint64
				for i, b := range f.buckets {
					cum += h.counts[i]
					writeSample(out, f.name+"_bucket", k, `le="`+num(b)+`"`, float64(cum))
				}
				writeSample(out, f.name+"_bucket", k, `le="+Inf"`, float64(h.count))
				writeSample(out, f.name+"_sum", k, "", h.sum)
				writeSample(out, f.name+"_count", k, "", float64(h.count))
			}
		}
	}
	cs := make([]func(*Writer), len(r.collectors))
	copy(cs, r.collectors)
	r.mu.Unlock()
	w := &Writer{w: out, declared: map[string]bool{}}
	for _, c := range cs {
		c(w)
	}
}

func writeSample(out io.Writer, name, labels, extra string, v float64) {
	switch {
	case labels != "" && extra != "":
		fmt.Fprintf(out, "%s{%s,%s} %s\n", name, labels, extra, num(v))
	case labels != "":
		fmt.Fprintf(out, "%s{%s} %s\n", name, labels, num(v))
	case extra != "":
		fmt.Fprintf(out, "%s{%s} %s\n", name, extra, num(v))
	default:
		fmt.Fprintf(out, "%s %s\n", name, num(v))
	}
}

func sortedKeys(m map[string]float64) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// Handler serves /metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.Write(w)
	})
}

// Serve listens on addr and serves /metrics until the listener fails.
func (r *Registry) Serve(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", r.Handler())
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}

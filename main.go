package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

type Cache struct {
	Name           string            `json:"name"`
	ActiveObjects  uint64            `json:"active_objects"`
	TotalObjects   uint64            `json:"total_objects"`
	ObjectSize     uint64            `json:"object_size"`
	ObjectsPerSlab uint64            `json:"objects_per_slab"`
	PagesPerSlab   uint64            `json:"pages_per_slab"`
	ActiveSlabs    uint64            `json:"active_slabs,omitempty"`
	TotalSlabs     uint64            `json:"total_slabs,omitempty"`
	Limit          uint64            `json:"limit,omitempty"`
	BatchCount     uint64            `json:"batch_count,omitempty"`
	SharedFactor   uint64            `json:"shared_factor,omitempty"`
	Sysfs          map[string]uint64 `json:"sysfs,omitempty"`
	Flags          map[string]bool   `json:"flags,omitempty"`
	Errors         []string          `json:"errors,omitempty"`
	Source         string            `json:"source"`
}

type Memory struct {
	Fields   map[string]uint64   `json:"fields_kib"`
	VMStat   map[string]uint64   `json:"vmstat"`
	PSI      map[string]Pressure `json:"psi,omitempty"`
	ZoneInfo []Zone              `json:"zones,omitempty"`
	Buddy    []Buddy             `json:"buddy,omitempty"`
}

type Pressure struct {
	Avg10  float64 `json:"avg10"`
	Avg60  float64 `json:"avg60"`
	Avg300 float64 `json:"avg300"`
	Total  uint64  `json:"total"`
}

type Zone struct {
	Node  int               `json:"node"`
	Name  string            `json:"name"`
	Pages map[string]uint64 `json:"pages"`
}

type Buddy struct {
	Node   int      `json:"node"`
	Zone   string   `json:"zone"`
	Orders []uint64 `json:"orders"`
}

type Snapshot struct {
	Schema      int       `json:"schema"`
	Time        time.Time `json:"time"`
	Host        string    `json:"host"`
	Kernel      string    `json:"kernel"`
	PageSize    uint64    `json:"page_size"`
	CacheSource string    `json:"cache_source"`
	Caches      []Cache   `json:"caches"`
	Memory      Memory    `json:"memory"`
	Warnings    []string  `json:"warnings,omitempty"`
}

type Metric struct {
	Name           string  `json:"name"`
	ActiveBytes    uint64  `json:"active_bytes"`
	AllocatedBytes uint64  `json:"allocated_bytes"`
	ReservedBytes  uint64  `json:"reserved_bytes"`
	WastedBytes    uint64  `json:"wasted_bytes"`
	ActiveObjects  uint64  `json:"active_objects"`
	TotalObjects   uint64  `json:"total_objects"`
	ObjectSize     uint64  `json:"object_size"`
	Utilization    float64 `json:"utilization_percent"`
	InternalWaste  float64 `json:"internal_waste_percent"`
	GrowthBytes    int64   `json:"growth_bytes,omitempty"`
	GrowthObjects  int64   `json:"growth_objects,omitempty"`
}

type Finding struct {
	Severity  string  `json:"severity"`
	Code      string  `json:"code"`
	Subject   string  `json:"subject"`
	Detail    string  `json:"detail"`
	Value     float64 `json:"value,omitempty"`
	Threshold float64 `json:"threshold,omitempty"`
}

type Report struct {
	Snapshot Snapshot  `json:"snapshot"`
	Metrics  []Metric  `json:"metrics"`
	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
}

type Summary struct {
	CacheCount     int     `json:"cache_count"`
	ActiveObjects  uint64  `json:"active_objects"`
	TotalObjects   uint64  `json:"total_objects"`
	ActiveBytes    uint64  `json:"active_bytes"`
	AllocatedBytes uint64  `json:"allocated_bytes"`
	ReservedBytes  uint64  `json:"reserved_bytes"`
	WastedBytes    uint64  `json:"wasted_bytes"`
	Utilization    float64 `json:"utilization_percent"`
	HighFindings   int     `json:"high_findings"`
	MediumFindings int     `json:"medium_findings"`
}

type Config struct {
	Proc         string
	Sys          string
	Debug        string
	Format       string
	Output       string
	Input        string
	Baseline     string
	Filter       string
	Sort         string
	Limit        int
	Interval     time.Duration
	Count        int
	MinBytes     uint64
	LowUtil      float64
	HighGrowth   uint64
	HighPSI      float64
	IncludeZone  bool
	IncludeBuddy bool
	IncludeSysfs bool
	Strict       bool
	Pretty       bool
	Verbose      bool
}

var sysfsNumeric = []string{
	"object_size", "objs_per_slab", "order", "slabs", "partial", "cpu_partial", "objects", "total_objects", "objects_partial", "slab_size", "aliases", "align", "hwcache_align", "red_zone", "poison", "store_user", "trace", "sanity_checks", "reclaim_account", "destroy_by_rcu", "shrink", "min_partial", "remote_node_defrag_ratio", "cpu_partial_slabs", "cpu_partial_free", "cpu_partial_alloc", "alloc_fastpath", "alloc_slowpath", "free_fastpath", "free_slowpath", "alloc_from_partial", "alloc_refill", "alloc_node_mismatch", "free_frozen", "free_add_partial", "free_remove_partial", "deactivate_to_head", "deactivate_to_tail", "deactivate_full", "deactivate_empty", "deactivate_remote_frees", "deactivate_bypass", "order_fallback", "cmpxchg_double_cpu_fail", "cmpxchg_double_fail", "alloc_slab", "alloc_slab_fallback", "free_slab", "free_slowpath", "objects_total", "slabs_cpu_partial", "slabs_partial", "slabs_full", "validate", "failslab", "usersize", "offset", "inuse", "slab_order", "reclaimable", "shrinkable",
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg := Config{}
	fs := flag.NewFlagSet("slab-forensics", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&cfg.Proc, "proc", "/proc", "procfs root")
	fs.StringVar(&cfg.Sys, "sys", "/sys", "sysfs root")
	fs.StringVar(&cfg.Debug, "debug", "/sys/kernel/debug", "debugfs root")
	fs.StringVar(&cfg.Format, "format", "table", "table, json, jsonl, csv")
	fs.StringVar(&cfg.Output, "output", "-", "output file or -")
	fs.StringVar(&cfg.Input, "input", "", "read snapshot from file")
	fs.StringVar(&cfg.Baseline, "baseline", "", "compare to baseline snapshot")
	fs.StringVar(&cfg.Filter, "filter", "", "regular expression on cache name")
	fs.StringVar(&cfg.Sort, "sort", "reserved", "reserved, active, wasted, objects, utilization, name, growth")
	fs.IntVar(&cfg.Limit, "limit", 30, "maximum displayed caches (0 means all)")
	fs.DurationVar(&cfg.Interval, "interval", 5*time.Second, "sampling interval")
	fs.IntVar(&cfg.Count, "count", 5, "number of samples (0 means continuous)")
	fs.Uint64Var(&cfg.MinBytes, "min-bytes", 0, "minimum reserved bytes")
	fs.Float64Var(&cfg.LowUtil, "low-util", 25, "low cache utilization threshold percent")
	fs.Uint64Var(&cfg.HighGrowth, "high-growth", 64*1024*1024, "growth alert threshold in bytes")
	fs.Float64Var(&cfg.HighPSI, "high-psi", 10, "memory PSI some avg10 alert threshold")
	fs.BoolVar(&cfg.IncludeZone, "zones", false, "collect zoneinfo")
	fs.BoolVar(&cfg.IncludeBuddy, "buddy", false, "collect buddyinfo")
	fs.BoolVar(&cfg.IncludeSysfs, "sysfs-details", true, "collect per-cache sysfs attributes")
	fs.BoolVar(&cfg.Strict, "strict", false, "fail on inaccessible optional files")
	fs.BoolVar(&cfg.Pretty, "pretty", true, "indent JSON output")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "print additional details")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "slab-forensics [flags] [snapshot|top|analyze|compare|watch|baseline|caches|memory|zones|buddy|diff|help]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmd := "snapshot"
	if fs.NArg() > 0 {
		cmd = fs.Arg(0)
	}
	if cmd == "help" {
		fs.Usage()
		return nil
	}
	switch cfg.Format {
	case "table", "json", "jsonl", "csv":
	default:
		return fmt.Errorf("unsupported format %q", cfg.Format)
	}
	if cfg.Limit < 0 {
		return errors.New("limit must not be negative")
	}
	if cfg.Interval <= 0 {
		return errors.New("interval must be positive")
	}
	if cfg.LowUtil < 0 || cfg.LowUtil > 100 {
		return errors.New("low-util must be between 0 and 100")
	}
	if cfg.Count < 0 {
		return errors.New("count must not be negative")
	}
	if cfg.HighPSI < 0 {
		return errors.New("high-psi must not be negative")
	}
	var re *regexp.Regexp
	if cfg.Filter != "" {
		var err error
		re, err = regexp.Compile(cfg.Filter)
		if err != nil {
			return err
		}
	}
	var baseline *Snapshot
	if cfg.Baseline != "" {
		b, err := loadSnapshot(cfg.Baseline)
		if err != nil {
			return err
		}
		baseline = &b
	}
	if cmd == "compare" || cmd == "diff" {
		if baseline == nil {
			return errors.New("compare requires -baseline")
		}
	}
	if cmd == "watch" {
		return watch(cfg, re, baseline)
	}
	snap, err := obtain(cfg)
	if err != nil {
		return err
	}
	if cmd == "baseline" {
		if cfg.Output == "-" {
			return errors.New("baseline requires -output filename")
		}
		return saveSnapshot(cfg.Output, snap)
	}
	rep := analyze(snap, baseline, cfg)
	return emit(cfg, cmd, rep, re)
}

func obtain(cfg Config) (Snapshot, error) {
	if cfg.Input != "" {
		return loadSnapshot(cfg.Input)
	}
	return collect(cfg)
}

func collect(cfg Config) (Snapshot, error) {
	host, _ := os.Hostname()
	s := Snapshot{Schema: 1, Time: time.Now().UTC(), Host: host, PageSize: uint64(os.Getpagesize()), Memory: Memory{Fields: map[string]uint64{}, VMStat: map[string]uint64{}, PSI: map[string]Pressure{}}}
	if b, err := os.ReadFile(filepath.Join(cfg.Proc, "sys/kernel/osrelease")); err == nil {
		s.Kernel = strings.TrimSpace(string(b))
	} else {
		s.Kernel = runtime.GOOS
	}
	caches, err := readSlabinfo(filepath.Join(cfg.Proc, "slabinfo"))
	if err != nil {
		return s, fmt.Errorf("read slabinfo: %w", err)
	}
	s.Caches = caches
	s.CacheSource = filepath.Join(cfg.Proc, "slabinfo")
	if cfg.IncludeSysfs {
		enhanceSysfs(&s, cfg)
	}
	if m, err := readKeyValues(filepath.Join(cfg.Proc, "meminfo"), true); err == nil {
		s.Memory.Fields = m
	} else {
		warn(&s, "meminfo: "+err.Error())
	}
	if m, err := readKeyValues(filepath.Join(cfg.Proc, "vmstat"), false); err == nil {
		s.Memory.VMStat = m
	} else {
		warn(&s, "vmstat: "+err.Error())
	}
	for _, name := range []string{"memory", "cpu", "io"} {
		p, err := readPSI(filepath.Join(cfg.Proc, "pressure", name))
		if err == nil {
			for k, v := range p {
				s.Memory.PSI[name+"_"+k] = v
			}
		} else if cfg.Strict {
			return s, err
		}
	}
	if cfg.IncludeZone {
		z, err := readZones(filepath.Join(cfg.Proc, "zoneinfo"))
		if err == nil {
			s.Memory.ZoneInfo = z
		} else {
			warn(&s, "zoneinfo: "+err.Error())
			if cfg.Strict {
				return s, err
			}
		}
	}
	if cfg.IncludeBuddy {
		b, err := readBuddy(filepath.Join(cfg.Proc, "buddyinfo"))
		if err == nil {
			s.Memory.Buddy = b
		} else {
			warn(&s, "buddyinfo: "+err.Error())
			if cfg.Strict {
				return s, err
			}
		}
	}
	if cfg.Strict && len(s.Warnings) > 0 {
		return s, errors.New(strings.Join(s.Warnings, "; "))
	}
	return s, nil
}

func readSlabinfo(path string) ([]Cache, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 64*1024), 4*1024*1024)
	result := make([]Cache, 0, 256)
	line := 0
	for scan.Scan() {
		line++
		s := strings.TrimSpace(scan.Text())
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "slabinfo -") {
			continue
		}
		fields := strings.Fields(s)
		if len(fields) < 6 {
			continue
		}
		values := make([]uint64, 5)
		valid := true
		for i := 0; i < 5; i++ {
			v, e := strconv.ParseUint(fields[i+1], 10, 64)
			if e != nil {
				valid = false
				break
			}
			values[i] = v
		}
		if !valid {
			continue
		}
		c := Cache{Name: fields[0], ActiveObjects: values[0], TotalObjects: values[1], ObjectSize: values[2], ObjectsPerSlab: values[3], PagesPerSlab: values[4], Source: "procfs"}
		for i := 6; i+1 < len(fields); i++ {
			if fields[i] == "slabdata" {
				c.ActiveSlabs, _ = strconv.ParseUint(fields[i+1], 10, 64)
				if i+2 < len(fields) {
					c.TotalSlabs, _ = strconv.ParseUint(fields[i+2], 10, 64)
				}
				break
			}
			if fields[i] == "tunables" {
				if i+3 < len(fields) {
					c.Limit, _ = strconv.ParseUint(fields[i+1], 10, 64)
					c.BatchCount, _ = strconv.ParseUint(fields[i+2], 10, 64)
					c.SharedFactor, _ = strconv.ParseUint(fields[i+3], 10, 64)
				}
			}
		}
		result = append(result, c)
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no slab caches parsed from %s", path)
	}
	return result, nil
}

func enhanceSysfs(s *Snapshot, cfg Config) {
	root := filepath.Join(cfg.Sys, "kernel/slab")
	entries, err := os.ReadDir(root)
	if err != nil {
		warn(s, "sysfs slab: "+err.Error())
		return
	}
	names := make(map[string]string, len(entries))
	for _, e := range entries {
		names[e.Name()] = filepath.Join(root, e.Name())
	}
	for i := range s.Caches {
		c := &s.Caches[i]
		path, ok := names[c.Name]
		if !ok {
			continue
		}
		c.Sysfs = make(map[string]uint64)
		c.Flags = make(map[string]bool)
		for _, key := range sysfsNumeric {
			b, err := os.ReadFile(filepath.Join(path, key))
			if err != nil {
				continue
			}
			raw := strings.TrimSpace(string(b))
			fields := strings.Fields(raw)
			if len(fields) == 0 {
				continue
			}
			v, err := strconv.ParseUint(fields[0], 10, 64)
			if err != nil {
				continue
			}
			c.Sysfs[key] = v
			switch key {
			case "red_zone", "poison", "store_user", "trace", "sanity_checks", "reclaim_account", "destroy_by_rcu", "hwcache_align":
				c.Flags[key] = v != 0
			}
		}
	}
}

func readKeyValues(path string, mem bool) (map[string]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSuffix(parts[0], ":")
		val, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			continue
		}
		if mem && len(parts) >= 3 && strings.EqualFold(parts[2], "kB") {
			out[key] = val
		} else {
			out[key] = val
		}
	}
	return out, sc.Err()
}

func readPSI(path string) (map[string]Pressure, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]Pressure{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		p := Pressure{}
		for _, field := range f[1:] {
			kv := strings.SplitN(field, "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "avg10":
				p.Avg10, _ = strconv.ParseFloat(kv[1], 64)
			case "avg60":
				p.Avg60, _ = strconv.ParseFloat(kv[1], 64)
			case "avg300":
				p.Avg300, _ = strconv.ParseFloat(kv[1], 64)
			case "total":
				p.Total, _ = strconv.ParseUint(kv[1], 10, 64)
			}
		}
		out[f[0]] = p
	}
	return out, nil
}

func readBuddy(path string) ([]Buddy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Buddy
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.ReplaceAll(sc.Text(), ",", "")
		p := strings.Fields(line)
		if len(p) < 5 || p[0] != "Node" || p[2] != "zone" {
			continue
		}
		node, err := strconv.Atoi(p[1])
		if err != nil {
			continue
		}
		b := Buddy{Node: node, Zone: p[3]}
		for _, field := range p[4:] {
			n, err := strconv.ParseUint(field, 10, 64)
			if err == nil {
				b.Orders = append(b.Orders, n)
			}
		}
		out = append(out, b)
	}
	return out, sc.Err()
}

func readZones(path string) ([]Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Zone
	sc := bufio.NewScanner(f)
	header := regexp.MustCompile(`^Node\s+(\d+),\s+zone\s+(\S+)`)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if m := header.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[1])
			out = append(out, Zone{Node: n, Name: m[2], Pages: map[string]uint64{}})
			continue
		}
		if len(out) == 0 {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		key := strings.TrimPrefix(f[0], "nr_")
		val, err := strconv.ParseUint(f[1], 10, 64)
		if err == nil {
			out[len(out)-1].Pages[key] = val
		}
	}
	return out, sc.Err()
}

func warn(s *Snapshot, msg string) { s.Warnings = append(s.Warnings, msg) }

func satMul(a, b uint64) uint64 {
	if a != 0 && b > math.MaxUint64/a {
		return math.MaxUint64
	}
	return a * b
}
func satAdd(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}
func satSub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}
func signedDiff(a, b uint64) int64 {
	if a >= b {
		d := a - b
		if d > math.MaxInt64 {
			return math.MaxInt64
		}
		return int64(d)
	}
	d := b - a
	if d > math.MaxInt64 {
		return math.MinInt64
	}
	return -int64(d)
}
func pct(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

func metric(c Cache, pageSize uint64) Metric {
	active := satMul(c.ActiveObjects, c.ObjectSize)
	allocated := satMul(c.TotalObjects, c.ObjectSize)
	reserved := allocated
	if c.TotalSlabs > 0 && c.PagesPerSlab > 0 {
		reserved = satMul(satMul(c.TotalSlabs, c.PagesPerSlab), pageSize)
	}
	if reserved < allocated {
		reserved = allocated
	}
	return Metric{Name: c.Name, ActiveBytes: active, AllocatedBytes: allocated, ReservedBytes: reserved, WastedBytes: satSub(reserved, active), ActiveObjects: c.ActiveObjects, TotalObjects: c.TotalObjects, ObjectSize: c.ObjectSize, Utilization: pct(c.ActiveObjects, c.TotalObjects), InternalWaste: pct(satSub(reserved, allocated), reserved)}
}

func analyze(s Snapshot, baseline *Snapshot, cfg Config) Report {
	r := Report{Snapshot: s, Metrics: make([]Metric, 0, len(s.Caches))}
	prior := map[string]Metric{}
	if baseline != nil {
		for _, c := range baseline.Caches {
			prior[c.Name] = metric(c, baseline.PageSize)
		}
	}
	for _, c := range s.Caches {
		m := metric(c, s.PageSize)
		if p, ok := prior[c.Name]; ok {
			m.GrowthBytes = signedDiff(m.ReservedBytes, p.ReservedBytes)
			m.GrowthObjects = signedDiff(m.ActiveObjects, p.ActiveObjects)
		}
		r.Metrics = append(r.Metrics, m)
		r.Summary.ActiveObjects = satAdd(r.Summary.ActiveObjects, c.ActiveObjects)
		r.Summary.TotalObjects = satAdd(r.Summary.TotalObjects, c.TotalObjects)
		r.Summary.ActiveBytes = satAdd(r.Summary.ActiveBytes, m.ActiveBytes)
		r.Summary.AllocatedBytes = satAdd(r.Summary.AllocatedBytes, m.AllocatedBytes)
		r.Summary.ReservedBytes = satAdd(r.Summary.ReservedBytes, m.ReservedBytes)
		r.Summary.WastedBytes = satAdd(r.Summary.WastedBytes, m.WastedBytes)
		if m.ReservedBytes >= 16*1024*1024 && m.Utilization < cfg.LowUtil {
			r.Findings = append(r.Findings, Finding{Severity: "medium", Code: "LOW_UTILIZATION", Subject: c.Name, Detail: "large slab cache with low active-object utilization", Value: m.Utilization, Threshold: cfg.LowUtil})
		}
		if baseline != nil && m.GrowthBytes > 0 && uint64(m.GrowthBytes) >= cfg.HighGrowth {
			r.Findings = append(r.Findings, Finding{Severity: "high", Code: "CACHE_GROWTH", Subject: c.Name, Detail: "cache reservation grew beyond configured threshold", Value: float64(m.GrowthBytes), Threshold: float64(cfg.HighGrowth)})
		}
		if c.ActiveObjects > c.TotalObjects {
			r.Findings = append(r.Findings, Finding{Severity: "high", Code: "INCONSISTENT_OBJECT_COUNTS", Subject: c.Name, Detail: "active objects exceed total objects"})
		}
		if c.ObjectSize == 0 {
			r.Findings = append(r.Findings, Finding{Severity: "medium", Code: "ZERO_OBJECT_SIZE", Subject: c.Name, Detail: "reported object size is zero"})
		}
		if c.TotalSlabs > 0 && c.PagesPerSlab > 0 && m.ReservedBytes > 0 && m.InternalWaste > 75 {
			r.Findings = append(r.Findings, Finding{Severity: "medium", Code: "HIGH_INTERNAL_WASTE", Subject: c.Name, Detail: "high difference between slab page reservation and object capacity", Value: m.InternalWaste, Threshold: 75})
		}
	}
	r.Summary.CacheCount = len(s.Caches)
	r.Summary.Utilization = pct(r.Summary.ActiveBytes, r.Summary.ReservedBytes)
	if p, ok := s.Memory.PSI["memory_some"]; ok && p.Avg10 >= cfg.HighPSI {
		r.Findings = append(r.Findings, Finding{Severity: "high", Code: "MEMORY_PRESSURE", Subject: "memory PSI", Detail: "memory stall average over 10 seconds exceeds threshold", Value: p.Avg10, Threshold: cfg.HighPSI})
	}
	if v := s.Memory.Fields["Slab"]; v > 0 {
		if rec := s.Memory.Fields["SReclaimable"]; rec > v {
			r.Findings = append(r.Findings, Finding{Severity: "medium", Code: "MEMINFO_INCONSISTENT", Subject: "meminfo", Detail: "SReclaimable exceeds Slab"})
		}
	}
	if baseline != nil {
		current := map[string]bool{}
		for _, c := range s.Caches {
			current[c.Name] = true
		}
		for name := range prior {
			if !current[name] {
				r.Findings = append(r.Findings, Finding{Severity: "info", Code: "CACHE_DISAPPEARED", Subject: name, Detail: "cache existed in baseline but not in current snapshot"})
			}
		}
		for _, c := range s.Caches {
			if _, ok := prior[c.Name]; !ok {
				r.Findings = append(r.Findings, Finding{Severity: "info", Code: "CACHE_ADDED", Subject: c.Name, Detail: "cache is new relative to baseline"})
			}
		}
	}
	for _, f := range r.Findings {
		switch f.Severity {
		case "high":
			r.Summary.HighFindings++
		case "medium":
			r.Summary.MediumFindings++
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := severity(r.Findings[i].Severity), severity(r.Findings[j].Severity)
		if a != b {
			return a > b
		}
		return r.Findings[i].Subject < r.Findings[j].Subject
	})
	return r
}

func severity(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func filterMetrics(metrics []Metric, cfg Config, re *regexp.Regexp) []Metric {
	out := make([]Metric, 0, len(metrics))
	for _, m := range metrics {
		if re != nil && !re.MatchString(m.Name) {
			continue
		}
		if m.ReservedBytes < cfg.MinBytes {
			continue
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch cfg.Sort {
		case "name":
			return a.Name < b.Name
		case "active":
			if a.ActiveBytes != b.ActiveBytes {
				return a.ActiveBytes > b.ActiveBytes
			}
		case "wasted":
			if a.WastedBytes != b.WastedBytes {
				return a.WastedBytes > b.WastedBytes
			}
		case "objects":
			if a.ActiveObjects != b.ActiveObjects {
				return a.ActiveObjects > b.ActiveObjects
			}
		case "utilization":
			if a.Utilization != b.Utilization {
				return a.Utilization < b.Utilization
			}
		case "growth":
			if a.GrowthBytes != b.GrowthBytes {
				return a.GrowthBytes > b.GrowthBytes
			}
		default:
			if a.ReservedBytes != b.ReservedBytes {
				return a.ReservedBytes > b.ReservedBytes
			}
		}
		return a.Name < b.Name
	})
	if cfg.Limit > 0 && len(out) > cfg.Limit {
		return out[:cfg.Limit]
	}
	return out
}

func emit(cfg Config, cmd string, rep Report, re *regexp.Regexp) error {
	var w io.Writer = os.Stdout
	if cfg.Output != "-" {
		f, err := os.Create(cfg.Output)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	metrics := filterMetrics(rep.Metrics, cfg, re)
	if cfg.Format == "json" || cfg.Format == "jsonl" {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		if cfg.Format == "json" && cfg.Pretty {
			enc.SetIndent("", "  ")
		}
		switch cmd {
		case "caches", "top":
			return enc.Encode(metrics)
		case "memory", "zones", "buddy":
			if cmd == "zones" {
				return enc.Encode(rep.Snapshot.Memory.ZoneInfo)
			}
			if cmd == "buddy" {
				return enc.Encode(rep.Snapshot.Memory.Buddy)
			}
			return enc.Encode(rep.Snapshot.Memory)
		case "analyze":
			return enc.Encode(struct {
				Summary  Summary   `json:"summary"`
				Findings []Finding `json:"findings"`
			}{rep.Summary, rep.Findings})
		default:
			return enc.Encode(rep)
		}
	}
	if cfg.Format == "csv" {
		return emitCSV(w, cmd, rep, metrics)
	}
	return emitTable(w, cmd, rep, metrics, cfg)
}

func emitCSV(w io.Writer, cmd string, rep Report, metrics []Metric) error {
	csvw := csv.NewWriter(w)
	defer csvw.Flush()
	if cmd == "analyze" {
		csvw.Write([]string{"severity", "code", "subject", "detail", "value", "threshold"})
		for _, f := range rep.Findings {
			csvw.Write([]string{f.Severity, f.Code, f.Subject, f.Detail, fmt.Sprint(f.Value), fmt.Sprint(f.Threshold)})
		}
		return csvw.Error()
	}
	csvw.Write([]string{"name", "active_objects", "total_objects", "object_size", "active_bytes", "allocated_bytes", "reserved_bytes", "wasted_bytes", "utilization_percent", "internal_waste_percent", "growth_bytes", "growth_objects"})
	for _, m := range metrics {
		csvw.Write([]string{m.Name, fmt.Sprint(m.ActiveObjects), fmt.Sprint(m.TotalObjects), fmt.Sprint(m.ObjectSize), fmt.Sprint(m.ActiveBytes), fmt.Sprint(m.AllocatedBytes), fmt.Sprint(m.ReservedBytes), fmt.Sprint(m.WastedBytes), fmt.Sprintf("%.4f", m.Utilization), fmt.Sprintf("%.4f", m.InternalWaste), fmt.Sprint(m.GrowthBytes), fmt.Sprint(m.GrowthObjects)})
	}
	return csvw.Error()
}

func emitTable(w io.Writer, cmd string, rep Report, metrics []Metric, cfg Config) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	s := rep.Snapshot
	fmt.Fprintf(tw, "HOST\t%s\nKERNEL\t%s\nTIME\t%s\nCACHES\t%d\nSLAB RESERVED\t%s\nACTIVE OBJECT BYTES\t%s\nUTILIZATION\t%.2f%%\nFINDINGS\t%d high, %d medium\n\n", s.Host, s.Kernel, s.Time.Format(time.RFC3339), rep.Summary.CacheCount, human(rep.Summary.ReservedBytes), human(rep.Summary.ActiveBytes), rep.Summary.Utilization, rep.Summary.HighFindings, rep.Summary.MediumFindings)
	switch cmd {
	case "memory":
		keys := sortedKeys(s.Memory.Fields)
		for _, k := range keys {
			fmt.Fprintf(tw, "%s\t%d KiB\n", k, s.Memory.Fields[k])
		}
		for k, v := range s.Memory.PSI {
			fmt.Fprintf(tw, "PSI %s\t%.2f / %.2f / %.2f\n", k, v.Avg10, v.Avg60, v.Avg300)
		}
	case "zones":
		for _, z := range s.Memory.ZoneInfo {
			fmt.Fprintf(tw, "NODE %d ZONE %s\n", z.Node, z.Name)
			for _, k := range sortedKeys(z.Pages) {
				fmt.Fprintf(tw, "  %s\t%d\n", k, z.Pages[k])
			}
		}
	case "buddy":
		for _, b := range s.Memory.Buddy {
			fmt.Fprintf(tw, "NODE %d\tZONE %s\t%v\n", b.Node, b.Zone, b.Orders)
		}
	case "analyze":
		fmt.Fprintln(tw, "SEVERITY\tCODE\tSUBJECT\tDETAIL")
		for _, f := range rep.Findings {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, f.Code, f.Subject, f.Detail)
		}
	default:
		fmt.Fprintln(tw, "CACHE\tACTIVE\tTOTAL\tSIZE\tRESERVED\tWASTE\tUTIL%\tGROWTH")
		for _, m := range metrics {
			fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\t%s\t%.1f\t%s\n", m.Name, m.ActiveObjects, m.TotalObjects, m.ObjectSize, human(m.ReservedBytes), human(m.WastedBytes), m.Utilization, humanSigned(m.GrowthBytes))
		}
		if cfg.Verbose {
			fmt.Fprintln(tw, "\nFINDINGS\nSEVERITY\tCODE\tSUBJECT\tDETAIL")
			for _, f := range rep.Findings {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, f.Code, f.Subject, f.Detail)
			}
		}
	}
	if cfg.Verbose {
		for _, v := range s.Warnings {
			fmt.Fprintf(tw, "WARNING\t%s\n", v)
		}
	}
	return nil
}

func human(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	v := float64(n)
	i := -1
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.2f %s", v, units[i])
}
func humanSigned(n int64) string {
	if n < 0 {
		if n == math.MinInt64 {
			return "-" + human(uint64(math.MaxInt64)+1)
		}
		return "-" + human(uint64(-n))
	}
	if n > 0 {
		return "+" + human(uint64(n))
	}
	return "0 B"
}
func sortedKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func loadSnapshot(path string) (Snapshot, error) {
	var s Snapshot
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 128*1024*1024))
	if err := dec.Decode(&s); err != nil {
		return s, err
	}
	if s.Schema != 1 {
		return s, fmt.Errorf("unsupported snapshot schema %d", s.Schema)
	}
	if s.PageSize == 0 {
		return s, errors.New("invalid snapshot page size")
	}
	if len(s.Caches) == 0 {
		return s, errors.New("snapshot has no caches")
	}
	return s, nil
}

func saveSnapshot(path string, s Snapshot) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".slab-forensics-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func watch(cfg Config, re *regexp.Regexp, baseline *Snapshot) error {
	count := 0
	var previous *Snapshot
	for cfg.Count == 0 || count < cfg.Count {
		s, err := obtain(cfg)
		if err != nil {
			return err
		}
		compare := baseline
		if compare == nil {
			compare = previous
		}
		r := analyze(s, compare, cfg)
		if count > 0 && cfg.Format == "table" {
			fmt.Println("\n---")
		}
		if err := emit(cfg, "snapshot", r, re); err != nil {
			return err
		}
		count++
		previous = &s
		if cfg.Count > 0 && count >= cfg.Count {
			break
		}
		time.Sleep(cfg.Interval)
	}
	return nil
}

func fingerprint(s Snapshot) string {
	var buf bytes.Buffer
	caches := append([]Cache(nil), s.Caches...)
	sort.Slice(caches, func(i, j int) bool { return caches[i].Name < caches[j].Name })
	for _, c := range caches {
		fmt.Fprintf(&buf, "%s:%d:%d:%d:%d\n", c.Name, c.ActiveObjects, c.TotalObjects, c.ObjectSize, c.TotalSlabs)
	}
	h := sha256.Sum256(buf.Bytes())
	return fmt.Sprintf("%x", h[:])
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }
func diskFree(path string) (uint64, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return 0, err
	}
	return satMul(s.Bavail, uint64(s.Bsize)), nil
}
func parseSize(s string) (uint64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	factor := uint64(1)
	for _, unit := range []struct {
		suffix string
		factor uint64
	}{{"gib", 1 << 30}, {"mib", 1 << 20}, {"kib", 1 << 10}, {"gb", 1000000000}, {"mb", 1000000}, {"kb", 1000}, {"g", 1 << 30}, {"m", 1 << 20}, {"k", 1 << 10}, {"b", 1}} {
		if strings.HasSuffix(s, unit.suffix) {
			factor = unit.factor
			s = strings.TrimSpace(strings.TrimSuffix(s, unit.suffix))
			break
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return satMul(n, factor), nil
}

func parseUnsigned(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n
}
func safeRatio(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}
func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }
func mapDifference(a, b map[string]uint64) map[string]int64 {
	out := map[string]int64{}
	for k, v := range a {
		out[k] = signedDiff(v, b[k])
	}
	for k, v := range b {
		if _, ok := a[k]; !ok {
			out[k] = -int64(minU(v, math.MaxInt64))
		}
	}
	return out
}
func minU(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
func maxU(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

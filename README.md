# slab-forensics

Linux SLAB/SLUB cache inspection, memory accounting, snapshot comparison, and terminal visualization in one Go source file.

## Design

`slab-forensics` is a read-only, Linux-oriented CLI instrument. It reads kernel virtual filesystems and analyzes per-cache object counts, estimated slab page reservations, system memory counters, pressure stall information, NUMA zones, and buddy allocator order counts. It uses the Go standard library only and requires no daemon or external Go modules.

The project is intended for Fedora, Rocky Linux, AlmaLinux, CentOS Stream, Oracle Linux, and other Linux systems exposing `/proc/slabinfo`. Kernel permissions and available sysfs attributes vary by distribution, kernel configuration, and privilege level.

## Build

```sh
go build -trimpath -o slab-forensics main.go
```

Run from the directory containing the executable:

```sh
sudo ./slab-forensics snapshot
sudo ./slab-forensics -limit 20 top
```

**Important:** This CLI uses Go's standard `flag` parser, so options must precede the subcommand:

```sh
sudo ./slab-forensics -limit 20 top
```

## Commands

| Command | Purpose |
| --- | --- |
| `snapshot` | Full current snapshot and analyzed metrics |
| `top` | Largest caches using selected sorting |
| `caches` | Cache metrics |
| `analyze` | Findings and summary |
| `memory` | `/proc/meminfo`, VM statistics, and PSI |
| `zones` | Optional `/proc/zoneinfo` analysis |
| `buddy` | Optional `/proc/buddyinfo` inspection |
| `baseline` | Save a schema-1 JSON snapshot atomically |
| `compare` / `diff` | Compare a snapshot with a saved baseline |
| `watch` | Repeated sampling, with append output for files |
| `topology` | Terminal utilization bars; optional truecolor |
| `help` | Show available flags |

## Examples

Capture and compare snapshots:

```sh
sudo ./slab-forensics -output before.json baseline
sudo ./slab-forensics -baseline before.json -limit 0 diff
sudo ./slab-forensics -baseline before.json -format json diff
```

Inspect caches and findings:

```sh
sudo ./slab-forensics -sort wasted -limit 25 top
sudo ./slab-forensics -filter 'dentry|inode|kmalloc' -limit 0 caches
sudo ./slab-forensics -low-util 20 -high-growth 33554432 analyze
```

Show topology:

```sh
sudo ./slab-forensics -color -limit 35 topology
sudo ./slab-forensics -sort utilization -color topology
```

Sample five times at ten-second intervals:

```sh
sudo ./slab-forensics -interval 10s -count 5 watch
sudo ./slab-forensics -interval 10s -count 5 -format jsonl -output samples.jsonl watch
```

Include physical memory context:

```sh
sudo ./slab-forensics -zones -buddy memory
sudo ./slab-forensics -zones -format csv zones
sudo ./slab-forensics -buddy -format csv buddy
```

Export cache metrics:

```sh
sudo ./slab-forensics -format csv -output caches.csv caches
sudo ./slab-forensics -format json -output report.json snapshot
```

Analyze a previously saved snapshot without accessing live slab data:

```sh
./slab-forensics -input before.json analyze
```

## Data sources

- `/proc/slabinfo`: per-cache object counts, object size, objects per slab, pages per slab, and slab counts when exposed.
- `/sys/kernel/slab`: optional per-cache allocator attributes and flags.
- `/proc/meminfo`: aggregate memory and slab counters.
- `/proc/vmstat`: virtual memory statistics.
- `/proc/pressure/{memory,cpu,io}`: pressure stall information, when available.
- `/proc/zoneinfo`: NUMA node and memory zone counters, enabled with `-zones`.
- `/proc/buddyinfo`: free block counts by buddy order, enabled with `-buddy`.

Use `-proc` and `-sys` to point to alternate filesystem roots, useful for fixture-based testing. The `-strict` option treats unavailable optional data as errors where supported.

## Memory accounting caveats

`active_bytes = active_objects * object_size`.

`allocated_bytes = total_objects * object_size`.

`reserved_bytes` estimates physical slab-page reservation from reported slab counts and pages per slab. If explicit slab counts are unavailable, it estimates the number of slabs from total objects and objects per slab. If neither is available, it falls back to allocated object bytes. Consequently, `reserved_bytes` is an **estimate**, not a verified resident-memory measurement.

`wasted_bytes = max(reserved_bytes - active_bytes, 0)` includes unused object slots and estimated page-level overhead. It is **not** a measure of memory that can necessarily be reclaimed. Kernel metadata, allocator alignment, partial slabs, per-CPU behavior, and concurrent changes can affect estimates.

`utilization_percent` is active objects divided by total objects for individual caches. Aggregate utilization is active object bytes divided by estimated reserved bytes, so these two percentages have different denominators.

Snapshots are non-atomic observations: the kernel can change between individual procfs and sysfs reads. A sudden change or anomaly should be corroborated by repeated sampling and `/proc/meminfo`.

The topology visualization represents **cache occupancy**, not the physical address layout of memory. Buddy allocator output describes free blocks by order, not a definitive fragmentation diagnosis.

## Baselines and monitoring

Baseline files use snapshot schema version 1. Comparisons include added, removed, changed, and unchanged caches; reserved-byte and active-object deltas are signed. Compare snapshots from the same host and preferably the same kernel and page size for meaningful interpretation.

`watch` appends to a specified output file instead of truncating it for each sample. `jsonl` is recommended for machine-readable monitoring. A finite `-count` is the default; `-count 0` runs until interrupted. `Ctrl+C` or termination signals stop sampling cleanly.

## Operational safety

The program does not write to procfs, sysfs, or debugfs. Output and baseline files are written to paths specified by the operator. Root privileges may be needed to read `/proc/slabinfo` or certain sysfs attributes. Avoid running with root privileges unless necessary.

Avoid enabling frequent detailed sysfs collection on extremely large hosts without considering sampling overhead. Monitoring output may contain hostnames and kernel details; handle exported reports appropriately.

## Limitations and validation

The project does not use BPF, kernel modules, or tracepoints, and cannot attribute allocations to individual call sites. Sysfs coverage depends on kernel configuration. The program has been compiled and checked with `go vet` using Go 1.23.2, but production validation on each target distribution is recommended.

Suggested validation:

```sh
GO111MODULE=off go test
go vet ./...
sudo ./slab-forensics -limit 10 snapshot
sudo ./slab-forensics -color -limit 10 topology
sudo ./slab-forensics -output before.json baseline
sudo ./slab-forensics -baseline before.json diff
```

Compare aggregate estimates against the `Slab`, `SReclaimable`, and `SUnreclaim` fields of `/proc/meminfo`. Differences do not automatically indicate a bug; allocator accounting and sampling semantics differ.

## License

GPL-3.0-or-later. See `LICENSE` for the full license text.

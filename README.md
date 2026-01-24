# pg_microbench
- `pg_microbench` allows you to measure hardware-level performance counters (CPU Cycles, Instructions, L1/LLC Cache Misses, Branch Mispredictions) for specific components of the PostgreSQL backend (Planner, Executor, Utility) or globally via SPI.
- The reason i made this because i wanted something different than attaching `perf stat` to backend pid every time..., Unlike `perf stat -p <pid>`, which captures everything a backend does (including idle ...etc) which is tbh not that much of a noise i know it doesn't matter a lot most of the time, but ! `pg_microbench` injects probes directly into postgres' hook infrastructure. This gives us more precise, per-query, per-component counters, which is nice anyways.

## Requirements

- **Linux Only**: Relies on the `perf_event_open` syscall. (
- **Privileges**: Requires access to hardware counters so: `sudo sysctl -w kernel.perf_event_paranoid=-1`

## Some things
- **Granular Profiling**: Hardware counters for planner, executor, utilities, any query (using SPI with `pg_microbench_run()`)
- **Some Metrics**: I only picked these 11 metrics, every other metric in perf is available but requires to register it which is easily done by hand when we want (see https://man7.org/linux/man-pages/man2/perf_event_open.2.html):
  - Wall Time (ns)
  - Cycles & Instructions (IPC)
  - Cache References & Misses (LLC)
  - L1 Data/Instruction Loads & Misses
  - Branches & Mispredictions
- **Output**: Results are printed as `NOTICE` messages directly in your `psql` session. (This is a personal ref since most of the times i run the benchmarks then just copy the numbers towards any LLM to do aggregates and draw graphs or whatever statistics visualization i need), it might a good idea to do something like `pg_stat_statements`, thats for another day.

## Usage

```bash
make
sudo make install
```
```sql
CREATE EXTENSION pg_microbench;
```

| GUC Variable             | Default | Description |
|--------------------------|---------|-------------|
| pg_microbench.enable     | off     | Master switch. Toggling this on initializes the Perf FDs. |
| pg_microbench.log        | on      | If on, prints metrics via NOTICE. |
| pg_microbench.scopes     | global  | Comma-separated list: `global`, `planner`, `executor`, `utility`. |

```sql

SET pg_microbench.enable = on;
SET pg_microbench.scopes = 'planner,executor'; -- (Comma seperated list, defaults to 'global' : see below)

-- Run your query
SELECT count(*) FROM some_table;

OUTPUT

NOTICE:  MICROBENCH [Executor]:
  wall_time_ns: 75166000
  cycles: 220050010
  instructions: 550010040
  L1-dcache-misses: 4500
  cache_misses: 120
  .....

NOTICE:  MICROBENCH [Planner]:
  wall_time_ns: 75166000
  cycles: 220050010
  instructions: 550010040
  L1-dcache-misses: 4500
  cache_misses: 120
  .....

SET pg_microbench.scopes = 'utility';
COPY t TO '/tmp/t_4096_none.txt' (FORMAT text);

NOTICE:  MICROBENCH [Utility]:
  wall_time_ns: 75166000
  cycles: 220050010
  instructions: 550010040
  L1-dcache-misses: 4500
  cache_misses: 120
  .....

SET pg_microbench.scopes = 'global';

-- Pass your query as a string
SELECT pg_microbench_run(
  'SELECT count(*) FROM generate_series(1, 1000000)'
);

NOTICE:  MICROBENCH [Global]:
  wall_time_ns: 1200000
  cycles: 3400000
  instructions: 8900000
  .....
```


#include "postgres.h"
#include "fmgr.h"
#include "optimizer/planner.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "utils/guc.h"
#include "utils/builtins.h"
#include "tcop/utility.h"
#include "utils/varlena.h"

#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <time.h>

PG_MODULE_MAGIC;

#define NUM_FIXED_METRICS 11

typedef enum
{
  SCOPE_GLOBAL = 0,
  SCOPE_PLANNER,
  SCOPE_UTILITY,
  SCOPE_EXECUTOR,
  SCOPE_COUNT
} ScopeType;

typedef struct
{
  char *name;
  uint32 type;
  uint32 config;
} MetricDef;

static MetricDef Metrics[NUM_FIXED_METRICS] = {
  {"wall_time_ns", PERF_TYPE_SOFTWARE, 0},
  {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
  {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
  {"branches", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
  {"branch_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
  {"cache_references", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES},
  {"cache_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES},
  {"L1-dcache-loads", PERF_TYPE_HW_CACHE,
    (PERF_COUNT_HW_CACHE_L1D) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16)},
  {"L1-dcache-misses", PERF_TYPE_HW_CACHE,
    (PERF_COUNT_HW_CACHE_L1D) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16)},
  {"L1-icache-loads", PERF_TYPE_HW_CACHE,
    (PERF_COUNT_HW_CACHE_L1I) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16)},
  {"L1-icache-misses", PERF_TYPE_HW_CACHE,
    (PERF_COUNT_HW_CACHE_L1I) | (PERF_COUNT_HW_CACHE_OP_READ << 8) | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16)},  
};

/* GUCs */
static bool pg_microbench_enable = false;
static bool pg_microbench_log = true;
static char *pg_microbench_scopes_str = NULL;

/* Perf file descriptors - initialized once per session */
static int active_fds[NUM_FIXED_METRICS];
static bool fds_initialized = false;

/* Scope configuration - refreshed on GUC change */
static bool scope_enabled[SCOPE_COUNT];
static bool config_valid = false;

/* Per-scope measurement state */
typedef struct {
  bool measuring;
  int depth;  /* Track nesting level */
  uint64 results[NUM_FIXED_METRICS];
  struct timespec start_ts;
} ScopeState;

static ScopeState scope_states[SCOPE_COUNT];

/* Hooks */
static planner_hook_type prev_planner_hook = NULL;
static ProcessUtility_hook_type prev_ProcessUtility_hook = NULL;
static ExecutorStart_hook_type prev_ExecutorStart_hook = NULL;
static ExecutorRun_hook_type prev_ExecutorRun_hook = NULL;
static ExecutorEnd_hook_type prev_ExecutorEnd_hook = NULL;

static long sys_perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                                 int cpu, int group_fd, unsigned long flags)
{
  return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static void init_perf_fds(void)
{
  int i;
  
  if (fds_initialized) return;
  
  for (i = 0; i < NUM_FIXED_METRICS; i++) {
    struct perf_event_attr pe;
    int fd;
    
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = Metrics[i].type;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = Metrics[i].config;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    fd = sys_perf_event_open(&pe, 0, -1, -1, 0);
    active_fds[i] = fd;  /* -1 if failed or unsupported counter... */
  }
  
  fds_initialized = true;
}

static void teardown_perf_fds(void)
{
  int i;
  
  if (!fds_initialized) return;
  
  for (i = 0; i < NUM_FIXED_METRICS; i++) {
    if (active_fds[i] != -1) {
      close(active_fds[i]);
      active_fds[i] = -1;
    }
  }
  
  fds_initialized = false;
}

static void refresh_config(void)
{
  char *raw_str;
  List *elemlist;
  ListCell *l;
  
  if (config_valid) return;
  
  memset(scope_enabled, 0, sizeof(scope_enabled));
  
  if (pg_microbench_scopes_str && pg_microbench_enable) {
    raw_str = pstrdup(pg_microbench_scopes_str);
    SplitGUCList(raw_str, ',', &elemlist);

    foreach(l, elemlist) {
      char *scope = (char *) lfirst(l); 
      if (pg_strcasecmp(scope, "global") == 0) {
        scope_enabled[SCOPE_GLOBAL] = true;
      } else if (pg_strcasecmp(scope, "planner") == 0) {
        scope_enabled[SCOPE_PLANNER] = true;
      } else if (pg_strcasecmp(scope, "utility") == 0) {
        scope_enabled[SCOPE_UTILITY] = true;
      } else if (pg_strcasecmp(scope, "executor") == 0) {
        scope_enabled[SCOPE_EXECUTOR] = true;
      }
    }
    
    pfree(raw_str);
    list_free(elemlist);
  }

  config_valid = true;
}

static void invalidate_config(void)
{
  config_valid = false;
}

static void start_measurement(ScopeType scope)
{
  ScopeState *state;
  int i;
  
  if (!pg_microbench_enable) return;
  
  state = &scope_states[scope];
  
  /* Avoid nested calls (like planner, sub queries ..etc), only measure the outermost */
  if (state->depth > 0) {
    state->depth++;
    return;
  }
  
  state->depth = 1;
  state->measuring = true;
  memset(state->results, 0, sizeof(state->results));
  
  /* Start wall clock */
  clock_gettime(CLOCK_MONOTONIC, &state->start_ts);
  
  /* Start perf counters */
  for (i = 1; i < NUM_FIXED_METRICS; i++) {
    if (active_fds[i] != -1) {
      ioctl(active_fds[i], PERF_EVENT_IOC_RESET, 0);
      ioctl(active_fds[i], PERF_EVENT_IOC_ENABLE, 0);
    }
  }
}

static void stop_measurement(ScopeType scope, const char *scope_name)
{
  ScopeState *state;
  struct timespec end_ts;
  uint64 elapsed_ns;
  StringInfoData buf;
  int i;
  ssize_t bytes_read;
  
  if (!pg_microbench_enable) return;
  
  state = &scope_states[scope];
  
  /* Avoid nested calls (like planner, sub queries ..etc), only measure the outermost */
  if (state->depth > 1) {
    state->depth--;
    return;
  }
  
  if (state->depth == 0 || !state->measuring) {
    return;  /* Not measuring */
  }
  
  state->depth = 0;
  state->measuring = false;
  
  /* Stop wall clock */
  clock_gettime(CLOCK_MONOTONIC, &end_ts);
  elapsed_ns = (end_ts.tv_sec - state->start_ts.tv_sec) * 1000000000ULL +
               (end_ts.tv_nsec - state->start_ts.tv_nsec);
  state->results[0] = elapsed_ns;
  
  /* Stop and read perf counters */
  for (i = 1; i < NUM_FIXED_METRICS; i++) {
    if (active_fds[i] != -1) {
      uint64 count = 0;
      ioctl(active_fds[i], PERF_EVENT_IOC_DISABLE, 0);
      bytes_read = read(active_fds[i], &count, sizeof(uint64));
      if (bytes_read > 0) {
        state->results[i] = count;
      }
    }
  }
  
  /* Log NOTICE results */
  if (pg_microbench_log) {
    initStringInfo(&buf);
    appendStringInfo(&buf, "MICROBENCH [%s]:\n", scope_name);
    
    for (i = 0; i < NUM_FIXED_METRICS; i++) {
      if (state->results[i] > 0 || i == 0) {
        appendStringInfo(&buf, "  %s: %lu\n", Metrics[i].name, state->results[i]);
      }
    }
    
    ereport(NOTICE, (errmsg_internal("%s", buf.data)));
    pfree(buf.data);
  }
}

/* GUC assign hooks to invalidate config */
static void guc_assign_enable(bool newval, void *extra)
{
  invalidate_config();

  // If pg_microbench.enable = on.
  if (newval) {
    init_perf_fds();
  } else {
    teardown_perf_fds();
  }
}

static void guc_assign_scopes(const char *newval, void *extra)
{
  invalidate_config();
}

static PlannedStmt *pg_microbench_planner(Query *parse, const char *query_string,
                                          int cursorOptions, ParamListInfo boundParams, ExplainState *es)
{
  PlannedStmt *result;
  bool should_measure;
  
  refresh_config();
  should_measure = pg_microbench_enable && scope_enabled[SCOPE_PLANNER];
  
  if (should_measure) {
    start_measurement(SCOPE_PLANNER);
  }

  if (prev_planner_hook) {
    result = prev_planner_hook(parse, query_string, cursorOptions, boundParams, es);
  } else {
    result = standard_planner(parse, query_string, cursorOptions, boundParams, es);
  }

  if (should_measure) {
    stop_measurement(SCOPE_PLANNER, "Planner");
  }

  return result;
}

static void pg_microbench_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
  refresh_config();

  if (prev_ExecutorStart_hook) {
    prev_ExecutorStart_hook(queryDesc, eflags);
  } else {
    standard_ExecutorStart(queryDesc, eflags);
  }
  
  /* Start executor measurement after ExecutorStart completes */
  if (pg_microbench_enable && scope_enabled[SCOPE_EXECUTOR]) {
    start_measurement(SCOPE_EXECUTOR);
  }
}

static void pg_microbench_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction, uint64 count)
{
  if (prev_ExecutorRun_hook) {
    prev_ExecutorRun_hook(queryDesc, direction, count);
  } else {
    standard_ExecutorRun(queryDesc, direction, count);
  }
}

static void pg_microbench_ExecutorEnd(QueryDesc *queryDesc)
{
  /* Stop executor measurement before ExecutorEnd */
  if (pg_microbench_enable && scope_enabled[SCOPE_EXECUTOR]) {
    stop_measurement(SCOPE_EXECUTOR, "Executor");
  }

  if (prev_ExecutorEnd_hook) {
    prev_ExecutorEnd_hook(queryDesc);
  } else {
    standard_ExecutorEnd(queryDesc);
  }
}

static void pg_microbench_ProcessUtility(PlannedStmt *pstmt,
                                         const char *queryString,
                                         bool readOnlyTree,
                                         ProcessUtilityContext context,
                                         ParamListInfo params,
                                         QueryEnvironment *queryEnv,
                                         DestReceiver *dest,
                                         QueryCompletion *qc)
{
  bool should_measure;
  
  refresh_config();
  should_measure = pg_microbench_enable && scope_enabled[SCOPE_UTILITY];
  
  if (should_measure) {
    start_measurement(SCOPE_UTILITY);
  }

  if (prev_ProcessUtility_hook) {
    prev_ProcessUtility_hook(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
  } else {
    standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
  }

  if (should_measure) {
    stop_measurement(SCOPE_UTILITY, "Utility");
  }
}

/* GLOBAL WRAPPER through SPI */
PG_FUNCTION_INFO_V1(pg_microbench_run);

Datum pg_microbench_run(PG_FUNCTION_ARGS)
{
  char *sql;
  int ret;
  bool should_measure;
  
  sql = text_to_cstring(PG_GETARG_TEXT_PP(0));
  
  refresh_config();
  should_measure = pg_microbench_enable && (scope_enabled[SCOPE_GLOBAL] || scope_enabled[SCOPE_PLANNER] ||
                                            scope_enabled[SCOPE_UTILITY] || scope_enabled[SCOPE_EXECUTOR]);
  
  if (!should_measure) {
    ereport(WARNING, 
            (errmsg("pg_microbench: global scope disabled. Use: SET pg_microbench.scopes='global';")));
  } else {
    start_measurement(SCOPE_GLOBAL);
  }

  SPI_connect();
  ret = SPI_execute(sql, false, 0);
  SPI_finish();

  if (should_measure) {
    stop_measurement(SCOPE_GLOBAL, "Global");
  }

  if (ret < 0) {
    elog(ERROR, "SPI execution failed: %d", ret);
  }

  PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(pg_microbench_version);

Datum pg_microbench_version(PG_FUNCTION_ARGS)
{
  PG_RETURN_TEXT_P(cstring_to_text("pg_microbench 1.0"));
}


void _PG_init(void)
{
  int i;
  
  for (i = 0; i < NUM_FIXED_METRICS; i++) {
    active_fds[i] = -1;
  }
  
  memset(scope_states, 0, sizeof(scope_states));

  DefineCustomBoolVariable("pg_microbench.enable",
                          "Enable microbenchmarking",
                          NULL,
                          &pg_microbench_enable,
                          false,
                          PGC_USERSET,
                          0,
                          NULL,
                          guc_assign_enable,
                          NULL);

  DefineCustomBoolVariable("pg_microbench.log",
                          "Log results via NOTICE",
                          NULL,
                          &pg_microbench_log,
                          true,
                          PGC_USERSET,
                          0, NULL, NULL, NULL);

  DefineCustomStringVariable("pg_microbench.scopes",
                            "Scopes: global, planner, executor, utility",
                            NULL,
                            &pg_microbench_scopes_str,
                            "global",
                            PGC_USERSET,
                            0,
                            NULL,
                            guc_assign_scopes,
                            NULL);

  prev_planner_hook = planner_hook;
  planner_hook = pg_microbench_planner;
  
  prev_ProcessUtility_hook = ProcessUtility_hook;
  ProcessUtility_hook = pg_microbench_ProcessUtility;
  
  prev_ExecutorStart_hook = ExecutorStart_hook;
  ExecutorStart_hook = pg_microbench_ExecutorStart;
  
  prev_ExecutorRun_hook = ExecutorRun_hook;
  ExecutorRun_hook = pg_microbench_ExecutorRun;
  
  prev_ExecutorEnd_hook = ExecutorEnd_hook;
  ExecutorEnd_hook = pg_microbench_ExecutorEnd;
}
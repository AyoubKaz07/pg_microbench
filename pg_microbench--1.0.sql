CREATE FUNCTION pg_microbench_run(sql text)
RETURNS void
AS 'MODULE_PATHNAME', 'pg_microbench_run'
LANGUAGE C STRICT;
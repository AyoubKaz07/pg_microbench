MODULES = pg_microbench
EXTENSION = pg_microbench
DATA = pg_microbench--1.0.sql
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
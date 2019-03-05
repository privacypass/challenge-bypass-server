#!/bin/sh
psql $DATABASE_URL --single-transaction -v ON_ERROR_STOP=1 -f $@

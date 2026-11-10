@echo off
set RISKBYTE_DEV_MODE=1
set RISKBYTE_ADMIN_TOKEN=dev-admin
set RISKBYTE_ANALYST_TOKEN=dev-analyst
set RISKBYTE_INGEST_TOKEN=dev-ingest
python -m riskbyte serve

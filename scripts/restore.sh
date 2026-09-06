#!/bin/bash
# Restore PostgreSQL — local prod-like
set -e
if [ -z "$1" ]; then
  echo "Usage: $0 <backup_file.sql>" >&2
  exit 1
fi
BACKUP_FILE="$1"
if [ ! -f "$BACKUP_FILE" ]; then
  echo "File not found: $BACKUP_FILE" >&2
  exit 1
fi
echo "Restoring $BACKUP_FILE..."
cat "$BACKUP_FILE" | docker exec -i security_postgres psql -U security -d security_saas -v ON_ERROR_STOP=1
echo "Restore complete"
echo "Running migrations..."
docker exec security_backend alembic upgrade head || echo "Migrations check failed (may be already at head)"
echo "Verifying..."
docker exec security_postgres psql -U security -d security_saas -c "SELECT count(*) FROM projects; SELECT count(*) FROM findings;"

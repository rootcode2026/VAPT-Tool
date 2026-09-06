#!/bin/bash
# Backup PostgreSQL — local prod-like
set -e
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="backup_${TIMESTAMP}.sql"
echo "Creating backup $BACKUP_FILE..."
docker exec security_postgres pg_dump -U security security_saas > "$BACKUP_FILE"
echo "Backup created: $BACKUP_FILE ($(wc -c < "$BACKUP_FILE") bytes)"
# Verify
if [ -s "$BACKUP_FILE" ]; then
  echo "Backup verified"
else
  echo "Backup failed" >&2
  exit 1
fi

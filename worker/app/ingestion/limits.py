"""Ingestion resource limits — safe defaults, env-overridable."""

import os

# Maximum archive file size (bytes) — reject larger uploads before extraction
MAX_ARCHIVE_SIZE = int(os.getenv("INGESTION_MAX_ARCHIVE_SIZE", str(100 * 1024 * 1024)))  # 100 MB

# Maximum total extracted size (bytes)
MAX_EXTRACTED_SIZE = int(os.getenv("INGESTION_MAX_EXTRACTED_SIZE", str(500 * 1024 * 1024)))  # 500 MB

# Maximum number of files in archive
MAX_FILE_COUNT = int(os.getenv("INGESTION_MAX_FILE_COUNT", "10000"))

# Maximum individual file size (bytes)
MAX_FILE_SIZE = int(os.getenv("INGESTION_MAX_FILE_SIZE", str(50 * 1024 * 1024)))  # 50 MB

# Maximum archive bomb ratio (extracted vs compressed) — not strict, but we enforce extracted size
MAX_ARCHIVE_BOMB_RATIO = int(os.getenv("INGESTION_MAX_BOMB_RATIO", "100"))

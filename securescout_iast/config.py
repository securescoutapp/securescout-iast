import os

# Base API endpoint for the SecureScout backend
DEFAULT_BACKEND_URL = os.environ.get("SECURESCOUT_BACKEND_URL", "https://api.getsecurescout.com")

# Maximum request body size (in bytes) we are willing to buffer for taint parsing (1MB)
MAX_BODY_SIZE_BYTES = 1_000_000

# Minimum string length required to register a taint value to prevent single-character false positives
TAINT_MIN_LENGTH = 6

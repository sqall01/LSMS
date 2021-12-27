from typing import Optional

# NOTE: If no "AlertR alert settings" and "Mail alert settings" are set to
# None, each script will fall back to print its output.

# AlertR alert settings.
ALERTR_FIFO = None  # type: Optional[str]

# Mail alert settings.
FROM_ADDR = None  # type: Optional[str]
TO_ADDR = None  # type: Optional[str]

# Directory to hold states in. Defaults to "/tmp" if not set.
STATE_DIR = "state"

# If "start_search.py" is used to execute all scripts, this setting configures
# the time in seconds before a script times out.
START_PROCESS_TIMEOUT = 60

from typing import List

# Is the script allowed to run or not?
ACTIVATED = True

# Directory in which cron stores crontab files for individual users. Following is the default on Ubuntu/Debian.
USER_CRONTAB_DIR = "/var/spool/cron/crontabs/"

# Directories in which scripts can be placed that are executed by cron. Following list are the defaults on Ubuntu/Debian.
CRON_SCRIPT_DIRS = ["/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly"]  # type: List[str]

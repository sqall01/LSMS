# Is the script allowed to run or not?
ACTIVATED = True

# Directories in which systemd unit files can be placed. Following list are the defaults on Ubuntu/Debian.
SYSTEMD_UNIT_DIRS = ["/etc/systemd/system",
                     "/etc/systemd/user",
                     "/etc/systemd/network",
                     "/usr/lib/systemd/system",
                     "/usr/lib/systemd/user",
                     "/usr/lib/systemd/network",
                     "/usr/local/lib/systemd/system",
                     "/usr/local/lib/systemd/user"
                     "/usr/local/lib/systemd/network",
                     "/lib/systemd/system",
                     "/lib/systemd/user",
                     "/lib/systemd/network"]  # type: List[str]

#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Searches for processes that were started by an SSH session that is now disconnected.

Requirements:
None

Reference:
https://twitter.com/CraigHRowland/status/1579582776529281026
"""

import os
import re
import sys

from lib.util import output_error, output_finding

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR
    from config.search_ssh_leftover_processes import ACTIVATED
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True


def search_leftover_ssh_process():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    # Search for SSH_CONNECTION and SSH_CLIENT
    fd = os.popen("grep -l SSH_C /proc/*/environ 2> /dev/null")
    ssh_processes = fd.read().strip()
    fd.close()

    for ssh_process in ssh_processes.split("\n"):
        # Example output: /proc/996/environ
        # noinspection RegExpRedundantEscape
        matches = re.search(r'proc/(\d*)/environ', ssh_process, re.IGNORECASE)
        if not matches:
            continue

        pid = matches.group(1)

        try:
            with open("/proc/" + str(pid) + "/status", "r") as fp:
                status_data = fp.read()

        except FileNotFoundError:  # Process got terminated while searching
            continue

        ppid = None
        name = None
        for line in status_data.split("\n"):
            if line.startswith("PPid:"):
                line_split = line.split("\t")

                try:
                    ppid = int(line_split[-1])
                except Exception as e:
                    output_error(__file__, "PPid not parsable for pid %d\n\n%s\n\n%s" % (pid, status_data, str(e)))
                    break

            elif line.startswith("Name:"):
                line_split = line.split("\t")
                name = line_split[-1]

            if ppid is not None and name is not None:
                break

        if ppid is not None and name is not None:
            if ppid == 1:

                # Get executed file
                exe_link = "/proc/" + str(pid) + "/exe"
                fd = os.popen("ls -laR %s" % exe_link)
                exe_raw = fd.read().strip()
                fd.close()
                matches = re.search(r'/proc/\d*/exe -> (.*)', exe_raw, re.IGNORECASE)
                exe_file = exe_raw
                if matches:
                    exe_file = matches.group(1)

                message = "Leftover process of SSH session found.\n\n"
                message += "Name: %s\n" % name
                message += "Exe: %s\n" % exe_file
                message += "Pid: %s\n" % pid

                output_finding(__file__, message)


if __name__ == '__main__':
    is_init_run = False
    if len(sys.argv) == 2:
        if sys.argv[1] == "--init":
            is_init_run = True

    # Script does not need to establish a state.
    if not is_init_run:
        search_leftover_ssh_process()

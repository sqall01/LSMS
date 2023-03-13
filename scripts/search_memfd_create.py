#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Malware uses calls such as memfd_create() to create an anonymous file in RAM that can be run.

Requirements:
None

Reference:
https://www.sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/
"""

import os
import sys

from lib.util import output_finding

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR
    from config.search_memfd_create import ACTIVATED
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True


def search_deleted_memfd_files():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    # Get all suspicious ELF files.
    fd = os.popen("ls -laR /proc/*/exe 2> /dev/null | grep memfd:.*\\(deleted\\)")
    suspicious_exe_raw = fd.read().strip()
    fd.close()

    suspicious_exes = []
    if suspicious_exe_raw.strip():
        suspicious_exes.extend(suspicious_exe_raw.strip().split("\n"))

    if suspicious_exes:
        message = "Deleted memfd file(s) found:\n\n"
        message += "\n".join(suspicious_exes)

        output_finding(__file__, message)


if __name__ == '__main__':
    is_init_run = False
    if len(sys.argv) == 2:
        if sys.argv[1] == "--init":
            is_init_run = True

    # Script does not need to establish a state.
    if not is_init_run:
        search_deleted_memfd_files()

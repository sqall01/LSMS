#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Use `debsums` to verify the integrity of installed deb packages using /var/lib/dpkg/info/*.md5sums.

Requirements:
`debsums` installed on system

Reference:
https://www.sandflysecurity.com/blog/detecting-linux-binary-file-poisoning/
"""

import os
import sys
from typing import List

from lib.util import output_finding

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR
    from config.verify_deb_packages import ACTIVATED, DEBSUMS_EXE, FILE_WHITELIST
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    DEBSUMS_EXE = "debsums"
    FILE_WHITELIST = []
    ACTIVATED = True


def _process_whitelist(changed_files: List[str]) -> List[str]:
    if not FILE_WHITELIST:
        return changed_files

    new_changed_files = []
    for changed_file in changed_files:
        if changed_file in FILE_WHITELIST:
            continue
        new_changed_files.append(changed_file)

    return new_changed_files


def verify_deb_packages():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    fd = os.popen("%s -c 2> /dev/null" % DEBSUMS_EXE)
    output_raw = fd.read().strip()
    fd.close()

    if output_raw != "":
        changed_files = output_raw.split("\n")

        changed_files = _process_whitelist(changed_files)

        if changed_files:
            message = "Changed deb package files found.\n\n"
            message += "\n".join(["File: %s" % x for x in changed_files])

            output_finding(__file__, message)


if __name__ == '__main__':
    is_init_run = False
    if len(sys.argv) == 2:
        if sys.argv[1] == "--init":
            is_init_run = True

    # Script does not need to establish a state.
    if not is_init_run:
        verify_deb_packages()

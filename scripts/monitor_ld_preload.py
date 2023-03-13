#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Monitor /etc/ld.so.preload for changes to detect malicious attempts to alter the control flow of binaries.

NOTE: The first execution of this script should be done with the argument "--init".
Otherwise, the script will only show you the current state of the environment since no state was established yet.
However, this assumes that the system is uncompromised during the initial execution.
Hence, if you are unsure this is the case you should verify the current state
before monitoring for changes will become an effective security measure.

Requirements:
None
"""

import os
import sys
from typing import Set

import lib.global_vars
from lib.state import load_state, store_state
from lib.util import output_error, output_finding

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.monitor_ld_preload import ACTIVATED
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))


def _get_ld_preload() -> Set[str]:
    path = "/etc/ld.so.preload"
    ld_data = set()
    if os.path.isfile(path):
        with open(path, 'rt') as fp:
            for line in fp:

                if line.strip() == "":
                    continue

                ld_data.add(line.strip())

    return ld_data


def monitor_ld_preload():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    stored_ld_data = set()
    try:
        state_data = load_state(STATE_DIR)

        # Convert list to set.
        if "ld_data" in state_data.keys():
            stored_ld_data = set(state_data["ld_data"])

    except Exception as e:
        output_error(__file__, str(e))
        return

    curr_ld_data = set()
    try:
        curr_ld_data = _get_ld_preload()

    except Exception as e:
        output_error(__file__, str(e))
        return

    # Compare stored data with current one.
    for stored_entry in stored_ld_data:
        if stored_entry not in curr_ld_data:
            message = "LD_PRELOAD entry '%s' was deleted." % stored_entry

            output_finding(__file__, message)

            continue

    # Check new data was added.
    for curr_entry in curr_ld_data:
        if curr_entry not in stored_ld_data:
            message = "LD_PRELOAD entry '%s' was added." % curr_entry

            output_finding(__file__, message)

    try:
        # Convert set to list.
        state_data = {"ld_data": list(curr_ld_data)}

        store_state(STATE_DIR, state_data)

    except Exception as e:
        output_error(__file__, str(e))


if __name__ == '__main__':
    if len(sys.argv) == 2:
        # Suppress output in our initial execution to establish a state.
        if sys.argv[1] == "--init":
            lib.global_vars.SUPPRESS_OUTPUT = True
    monitor_ld_preload()

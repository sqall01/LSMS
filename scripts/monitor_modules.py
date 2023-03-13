#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Monitor /proc/modules for changes to detect if a malicious module was loaded. The script can run in two different modes:
1) before running the script, whitelist every module that is allowed to be loaded on the host in the configuration file.
2) assume all loaded modules are legitimate during the initial execution of the script with "--init" and monitor for changes.

If using 1), you get fewer false-positives due to the time you spend setting everything up.
If using 2), you assume the host is uncompromised during the initial execution of the script.
If you have a module that is loaded/unloaded frequently, you can still configure the whitelist additionally
to prevent constant alerting.

Requirements:
None
"""

import os
import sys

import lib.global_vars
from lib.state import load_state, store_state
from lib.util import output_error, output_finding

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.monitor_modules import ACTIVATED, MODULES_WHITELIST
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    MODULES_WHITELIST = []
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))


def _get_modules():
    """
    Reads all currently loaded modules.
    :return: set of loaded modules
    """
    loaded_modules = set()
    with open("/proc/modules", 'r') as fp:
        for line in fp:
            line_list = line.split(" ")
            loaded_modules.add(line_list[0])
    return loaded_modules


def monitor_modules():
    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    stored_modules_data = set()
    try:
        state_data = load_state(STATE_DIR)

        # Convert list to set.
        if "modules_data" in state_data.keys():
            stored_modules_data = set(state_data["modules_data"])

    except Exception as e:
        output_error(__file__, str(e))
        return

    current_modules = set()
    try:
        current_modules = _get_modules()

    except Exception as e:
        output_error(__file__, str(e))
        return

    # Remove whitelisted modules from the currently loaded modules set.
    current_modules = current_modules - set(MODULES_WHITELIST)

    # Check for newly loaded modules.
    loaded_modules = current_modules - stored_modules_data
    if loaded_modules:
        message = "New modules loaded.\n\n"
        message += "Entries:\n"
        for module in loaded_modules:
            message += module
            message += "\n"

        output_finding(__file__, message)

    # Check for newly unloaded modules.
    unloaded_modules = stored_modules_data - current_modules
    if unloaded_modules:
        message = "Running modules unloaded.\n\n"
        message += "Entries:\n"
        for module in unloaded_modules:
            message += module
            message += "\n"

        output_finding(__file__, message)

    try:
        # Convert set to list.
        state_data = {"modules_data": list(current_modules)}

        store_state(STATE_DIR, state_data)

    except Exception as e:
        output_error(__file__, str(e))


if __name__ == '__main__':
    if len(sys.argv) == 2:
        # Suppress output in our initial execution to establish a state.
        if sys.argv[1] == "--init":
            lib.global_vars.SUPPRESS_OUTPUT = True
    monitor_modules()

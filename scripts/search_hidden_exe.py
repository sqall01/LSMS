#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Searches for hidden ELF files in the filesystem. Usually, ELF binaries are not hidden in a Linux environment.

Requirements:
None
"""

import os
import sys
from typing import List

from lib.step_state import StepLocation, load_step_state, store_step_state
from lib.util import output_error, output_finding
from lib.util_file import FileLocation, apply_directory_whitelist, apply_file_whitelist

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.search_hidden_exe import ACTIVATED, SEARCH_IN_STEPS, SEARCH_LOCATIONS, \
        HIDDEN_EXE_DIRECTORY_WHITELIST, HIDDEN_EXE_FILE_WHITELIST

    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    SEARCH_IN_STEPS = False
    SEARCH_LOCATIONS = ["/"]
    HIDDEN_EXE_DIRECTORY_WHITELIST = []
    HIDDEN_EXE_FILE_WHITELIST = []
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))


def search_hidden_exe_files():
    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    step_state_data = {}
    try:
        step_state_data = load_step_state(STATE_DIR)

    except Exception as e:
        output_error(__file__, str(e))
        return

    # Reset step if we do not search in steps but everything.
    if not SEARCH_IN_STEPS:
        step_state_data["next_step"] = 0

    if not SEARCH_LOCATIONS:
        SEARCH_LOCATIONS.append("/")

    # Gather all search locations.
    search_locations = []  # type: List[StepLocation]
    # If SEARCH_IN_STEPS is active, build a list of directories to search in
    if SEARCH_IN_STEPS:
        for search_location in SEARCH_LOCATIONS:

            # Add parent directory as non-recursive search location in order to search in it without going deeper.
            search_locations.append(StepLocation(search_location, False))

            # Add all containing subdirectories as recursive search locations.
            elements = os.listdir(search_location)
            elements.sort()
            for element in elements:
                path = os.path.join(search_location, element)
                if os.path.isdir(path):
                    search_locations.append(StepLocation(path, True))

    # If we do not search in separated steps, just add each directory as a recursive search location.
    else:
        for search_location in SEARCH_LOCATIONS:
            search_locations.append(StepLocation(search_location, True))

    # Reset index if it is outside the search locations.
    if step_state_data["next_step"] >= len(search_locations):
        step_state_data["next_step"] = 0

    while True:
        search_location_obj = search_locations[step_state_data["next_step"]]

        # Get all hidden ELF files.
        if search_location_obj.search_recursive:
            fd = os.popen("find %s -type f -iname \".*\" -exec echo -n \"{} \" \\; -exec head -c 4 {} \\; -exec echo \"\" \\; | grep -P \"\\x7fELF\""
                          % search_location_obj.location)

        else:
            fd = os.popen("find %s -maxdepth 1 -type f -iname \".*\" -exec echo -n \"{} \" \\; -exec head -c 4 {} \\; -exec echo \"\" \\; | grep -P \"\\x7fELF\""
                          % search_location_obj.location)
        output_raw = fd.read().strip()
        fd.close()

        if output_raw != "":

            hidden_files = []  # type: List[FileLocation]
            output_list = output_raw.split("\n")
            for output_entry in output_list:
                file_location = output_entry[:-5]
                hidden_files.append(FileLocation(file_location))

            dir_whitelist = [FileLocation(x) for x in HIDDEN_EXE_DIRECTORY_WHITELIST]
            file_whitelist = [FileLocation(x) for x in HIDDEN_EXE_FILE_WHITELIST]

            hidden_files = apply_directory_whitelist(dir_whitelist, hidden_files)
            hidden_files = apply_file_whitelist(file_whitelist, hidden_files)

            if hidden_files:
                message = "Hidden ELF file(s) found:\n\n"
                message += "\n".join(["File: %s" % x.location for x in hidden_files])

                output_finding(__file__, message)

        step_state_data["next_step"] += 1

        # Stop search if we are finished.
        if SEARCH_IN_STEPS or step_state_data["next_step"] >= len(search_locations):
            break

    try:
        store_step_state(STATE_DIR, step_state_data)

    except Exception as e:
        output_error(__file__, str(e))


if __name__ == '__main__':
    is_init_run = False
    if len(sys.argv) == 2:
        if sys.argv[1] == "--init":
            is_init_run = True

    # Script does not need to establish a state.
    if not is_init_run:
        search_hidden_exe_files()

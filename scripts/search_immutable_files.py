#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Searches for immutable files in the filesystem.

Requirements:
None
"""

import os
import sys
from typing import List, cast

from lib.step_state import StepLocation, load_step_state, store_step_state
from lib.util import output_error, output_finding
from lib.util_file import FileLocation, apply_directory_whitelist, apply_file_whitelist

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.search_immutable_files import ACTIVATED, SEARCH_IN_STEPS, SEARCH_LOCATIONS, \
        IMMUTABLE_DIRECTORY_WHITELIST, IMMUTABLE_FILE_WHITELIST

    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    SEARCH_IN_STEPS = False
    SEARCH_LOCATIONS = ["/"]
    IMMUTABLE_DIRECTORY_WHITELIST = []
    IMMUTABLE_FILE_WHITELIST = []
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))


class ImmutableFile(FileLocation):
    def __init__(self, location: str, attribute: str):
        super().__init__(location)
        self._attribute = attribute

    @property
    def attribute(self) -> str:
        return self._attribute


def search_immutable_files():
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

        # Get all immutable files.
        if search_location_obj.search_recursive:
            fd = os.popen("lsattr -R -a %s 2> /dev/null | sed -rn '/^[aAcCdDeijPsStTu\\-]{4}i/p'"
                          % search_location_obj.location)

        else:
            fd = os.popen("lsattr -a %s 2> /dev/null | sed -rn '/^[aAcCdDeijPsStTu\\-]{4}i/p'"
                          % search_location_obj.location)
        output_raw = fd.read().strip()
        fd.close()

        if output_raw != "":

            immutable_files = []  # type: List[ImmutableFile]
            output_list = output_raw.split("\n")
            for output_entry in output_list:
                output_entry_list = output_entry.split(" ")

                # Notify and skip line if sanity check fails.
                if len(output_entry_list) != 2:
                    output_error(__file__, "Unable to process line '%s'" % output_entry)
                    continue

                attributes = output_entry_list[0]
                file_location = output_entry_list[1]
                immutable_files.append(ImmutableFile(file_location, attributes))

            dir_whitelist = [FileLocation(x) for x in IMMUTABLE_DIRECTORY_WHITELIST]
            file_whitelist = [FileLocation(x) for x in IMMUTABLE_FILE_WHITELIST]

            immutable_files = cast(List[ImmutableFile], apply_directory_whitelist(dir_whitelist, immutable_files))
            immutable_files = cast(List[ImmutableFile], apply_file_whitelist(file_whitelist, immutable_files))

            if immutable_files:
                message = "Immutable file(s) found:\n\n"
                message += "\n".join(["File: %s; Attributes: %s" % (x.location, x.attribute) for x in immutable_files])

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
        search_immutable_files()

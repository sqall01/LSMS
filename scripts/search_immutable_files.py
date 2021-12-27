#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# # Licensed under the MIT License.

"""
Short summary:
Searches for immutable files in the filesystem.

Requirements:
None
"""

import os
import json
import socket
import stat
from typing import Dict, Any, List, Tuple

from lib.alerts import raise_alert_alertr, raise_alert_mail

# Read configuration and library functions.
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

MAIL_SUBJECT = "[Security] Searching immutable files on host '%s'" % socket.gethostname()


class SearchImmutableException(Exception):
    def __init__(self, msg: str):
        self._msg = msg

    def __str__(self):
        return self._msg


def _load_state() -> Dict[str, Any]:
    state_file = os.path.join(STATE_DIR, "state")
    state_data = {"next_step": 0}
    if os.path.isfile(state_file):
        data = None
        try:
            with open(state_file, 'rt') as fp:
                data = fp.read()
            if data is None:
                raise SearchImmutableException("Read state data is None.")

            state_data = json.loads(data)

        except Exception as e:
            raise SearchImmutableException("State data: '%s'; Exception: '%s'" % (str(data), str(e)))

    return state_data


def _output_error(msg: str):
    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if print_output:
        print(msg)

    else:
        hostname = socket.gethostname()
        message = "Error searching immutable files on host on host '%s': %s" \
                  % (hostname, msg)

        if ALERTR_FIFO:
            optional_data = dict()
            optional_data["error"] = True
            optional_data["message"] = message

            raise_alert_alertr(ALERTR_FIFO,
                               optional_data)

        if FROM_ADDR is not None and TO_ADDR is not None:
            raise_alert_mail(FROM_ADDR,
                             TO_ADDR,
                             MAIL_SUBJECT,
                             message)


def _process_directory_whitelist(immutable_files: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    if not IMMUTABLE_DIRECTORY_WHITELIST:
        return immutable_files

    # Extract the components of the whitelist paths (pre-process it to reduces processing steps).
    whitelist_path_components_list = []
    for whitelist_entry in IMMUTABLE_DIRECTORY_WHITELIST:
        whitelist_path = os.path.normpath(whitelist_entry)
        whitelist_path_components = []
        while True:
            whitelist_path, component = os.path.split(whitelist_path)
            if not component:
                break
            whitelist_path_components.insert(0, component)
        whitelist_path_components_list.append(whitelist_path_components)

    new_immutable_files = []
    for immutable_file in immutable_files:
        is_whitelisted = False

        # Extract the components of the path to the immutable file.
        immutable_path = os.path.dirname(os.path.normpath(immutable_file[0]))
        immutable_path_components = []
        while True:
            immutable_path, component = os.path.split(immutable_path)
            if not component:
                break
            immutable_path_components.insert(0, component)

        for whitelist_path_components in whitelist_path_components_list:

            # Skip case such as "whitelist: /usr/local/bin" and "immutable path: /usr"
            if len(whitelist_path_components) > len(immutable_path_components):
                continue

            # NOTE: this check also works if "/" is whitelisted, since the whitelist components are empty and
            # thus the file is counted as whitelisted.
            is_whitelisted = True
            for i in range(len(whitelist_path_components)):
                if whitelist_path_components[i] != immutable_path_components[i]:
                    is_whitelisted = False
            if is_whitelisted:
                break

        if not is_whitelisted:
            new_immutable_files.append(immutable_file)
    return new_immutable_files


def _process_file_whitelist(immutable_files: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    if not IMMUTABLE_FILE_WHITELIST:
        return immutable_files

    new_immutable_files = []
    for immutable_file in immutable_files:
        is_whitelisted = False
        for whitelist_entry in IMMUTABLE_FILE_WHITELIST:
            if os.path.samefile(immutable_file[0], whitelist_entry):
                is_whitelisted = True
                break
        if not is_whitelisted:
            new_immutable_files.append(immutable_file)
    return new_immutable_files


def _store_state(state_data: Dict[str, Any]):
    # Create state dir if it does not exist.
    if not os.path.exists(STATE_DIR):
        os.makedirs(STATE_DIR)

    state_file = os.path.join(STATE_DIR, "state")

    with open(state_file, 'wt') as fp:
        fp.write(json.dumps(state_data))

    os.chmod(state_file, stat.S_IREAD | stat.S_IWRITE)


def search_immutable_files():
    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    state_data = {}
    try:
        state_data = _load_state()

    except Exception as e:
        _output_error(str(e))
        return

    # Reset step if we do not search in steps but everything.
    if not SEARCH_IN_STEPS:
        state_data["next_step"] = 0

    if not SEARCH_LOCATIONS:
        SEARCH_LOCATIONS.append("/")

    # Gather all search locations.
    search_locations = []
    # If SEARCH_IN_STEPS is active, build a list of directories to search in
    if SEARCH_IN_STEPS:
        for search_location in SEARCH_LOCATIONS:

            # Add parent directory as non-recursive search location in order to search in it without going deeper.
            # Tuple with directory as first element and recursive search as second element.
            search_locations.append((search_location, False))

            # Add all containing sub-directories as recursive search locations.
            elements = os.listdir(search_location)
            elements.sort()
            for element in elements:
                path = os.path.join(search_location, element)
                if os.path.isdir(path):
                    # Tuple with directory as first element and recursive search as second element.
                    search_locations.append((path, True))

    # If we do not search in separated steps, just add each directory as a recursive search location.
    else:
        for search_location in SEARCH_LOCATIONS:
            # Tuple with directory as first element and recursive search as second element.
            search_locations.append((search_location, True))

    # Reset index if it is outside the search locations.
    if state_data["next_step"] >= len(search_locations):
        state_data["next_step"] = 0

    while True:
        search_location, is_recursive = search_locations[state_data["next_step"]]

        # Get all immutable files.
        if is_recursive:
            fd = os.popen("lsattr -R -a %s 2> /dev/null | sed -rn '/^[aAcCdDeijPsStTu\\-]{4}i/p'"
                          % search_location)

        else:
            fd = os.popen("lsattr -a %s 2> /dev/null | sed -rn '/^[aAcCdDeijPsStTu\\-]{4}i/p'"
                          % search_location)
        output_raw = fd.read().strip()
        fd.close()

        if output_raw != "":

            immutable_files = []
            output_list = output_raw.split("\n")
            for output_entry in output_list:
                output_entry_list = output_entry.split(" ")

                # Notify and skip line if sanity check fails.
                if len(output_entry_list) != 2:
                    _output_error("Unable to process line '%s'" % output_entry)
                    continue

                attributes = output_entry_list[0]
                file_location = output_entry_list[1]
                immutable_files.append((file_location, attributes))

            immutable_files = _process_directory_whitelist(immutable_files)
            immutable_files = _process_file_whitelist(immutable_files)

            hostname = socket.gethostname()
            message = "Immutable files found on host '%s'.\n\n" % hostname
            message += "\n".join(["File: %s; Attributes: %s" % (x[0], x[1]) for x in immutable_files])

            if print_output:
                print(message)
                print("#" * 80)

            if ALERTR_FIFO:
                optional_data = dict()
                optional_data["immutable_files"] = output_raw.split("\n")
                optional_data["hostname"] = hostname
                optional_data["message"] = message

                raise_alert_alertr(ALERTR_FIFO,
                                   optional_data)

            if FROM_ADDR is not None and TO_ADDR is not None:
                raise_alert_mail(FROM_ADDR,
                                 TO_ADDR,
                                 MAIL_SUBJECT,
                                 message)

        state_data["next_step"] += 1

        # Stop search if we are finished.
        if SEARCH_IN_STEPS or state_data["next_step"] >= len(search_locations):
            break

    try:
        _store_state(state_data)

    except Exception as e:
        _output_error(str(e))


if __name__ == '__main__':
    search_immutable_files()

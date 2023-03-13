#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Monitor ~/.ssh/authorized_keys for changes to detect malicious backdoor attempts.

NOTE: The first execution of this script should be done with the argument "--init".
Otherwise, the script will only show you the current state of the environment since no state was established yet.
However, this assumes that the system is uncompromised during the initial execution.
Hence, if you are unsure this is the case you should verify the current state
before monitoring for changes will become an effective security measure.

Requirements:
None
"""

import os
import stat
import sys
from typing import List, Tuple, Dict, Any

import lib.global_vars
from lib.state import load_state, store_state
from lib.util import output_error, output_finding
from lib.util_user import get_system_users

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.monitor_ssh_authorized_keys import ACTIVATED
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))


class MonitorSSHException(Exception):
    pass


def _get_home_dirs() -> List[Tuple[str, str]]:
    return [(x.name, x.home) for x in get_system_users()]


def _get_system_ssh_data() -> List[Dict[str, Any]]:
    ssh_data = []
    user_home_list = _get_home_dirs()

    for user, home in user_home_list:
        # Monitor "authorized_keys2" too since SSH also checks this file for keys (even though it is deprecated).
        for authorized_file_name in ["authorized_keys", "authorized_keys2"]:
            authorized_keys_file = os.path.join(home, ".ssh", authorized_file_name)
            if os.path.isfile(authorized_keys_file):
                ssh_user_data = {"user": user,
                                 "authorized_keys_file": authorized_keys_file,
                                 "authorized_keys_entries": _parse_authorized_keys_file(authorized_keys_file)}
                ssh_data.append(ssh_user_data)
    return ssh_data


def _parse_authorized_keys_file(authorized_keys_file: str) -> List[str]:
    entries = set()
    try:
        with open(authorized_keys_file, 'rt') as fp:
            for line in fp:
                entries.add(line.strip())

    except Exception as e:
        raise MonitorSSHException("Unable to parse file '%s'; Exception: '%s'" % (authorized_keys_file, str(e)))

    return list(entries)


def monitor_ssh_authorized_keys():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    stored_ssh_data = []
    curr_ssh_data = []
    try:
        state_data = load_state(STATE_DIR)
        if "ssh_data" in state_data.keys():
            stored_ssh_data = state_data["ssh_data"]
        curr_ssh_data = _get_system_ssh_data()

    except Exception as e:
        output_error(__file__, str(e))
        return

    # Check if any authorized_keys file is world writable.
    for curr_entry in curr_ssh_data:
        authorized_keys_file = curr_entry["authorized_keys_file"]
        file_stat = os.stat(authorized_keys_file)
        if file_stat.st_mode & stat.S_IWOTH:
            message = "SSH authorized_keys file for user '%s' is world writable." % curr_entry["user"]

            output_finding(__file__, message)

    # Compare stored data with current one.
    for stored_entry in stored_ssh_data:

        # Extract current entry belonging to the same user.
        curr_user_entry = None
        for curr_entry in curr_ssh_data:
            if stored_entry["user"] == curr_entry["user"]:
                curr_user_entry = curr_entry
                break
        if curr_user_entry is None:
            message = "SSH authorized_keys file for user '%s' was deleted." % stored_entry["user"]

            output_finding(__file__, message)
            continue

        # Check authorized_keys path has changed.
        if stored_entry["authorized_keys_file"] != curr_user_entry["authorized_keys_file"]:
            message = "SSH authorized_keys location for user '%s' changed from '%s' to '%s'." \
                      % (stored_entry["user"],
                         stored_entry["authorized_keys_file"],
                         curr_user_entry["authorized_keys_file"])

            output_finding(__file__, message)

        # Check authorized_key was removed.
        for authorized_key in stored_entry["authorized_keys_entries"]:
            if authorized_key not in curr_user_entry["authorized_keys_entries"]:
                message = "SSH authorized_keys entry was removed.\n\n"
                message += "Entry: %s" % authorized_key

                output_finding(__file__, message)

        # Check authorized_key was added.
        for authorized_key in curr_user_entry["authorized_keys_entries"]:
            if authorized_key not in stored_entry["authorized_keys_entries"]:
                message = "SSH authorized_keys entry was added.\n\n"
                message += "Entry: %s" % authorized_key

                output_finding(__file__, message)

    for curr_entry in curr_ssh_data:
        found = False
        for stored_entry in stored_ssh_data:
            if curr_entry["user"] == stored_entry["user"]:
                found = True
                break
        if not found:
            message = "New authorized_keys file was added for user '%s'.\n\n" % curr_entry["user"]
            message += "Entries:\n"
            for authorized_key in curr_entry["authorized_keys_entries"]:
                message += authorized_key
                message += "\n"

            output_finding(__file__, message)

    try:
        state_data["ssh_data"] = curr_ssh_data
        store_state(STATE_DIR, state_data)

    except Exception as e:
        output_error(__file__, str(e))


if __name__ == '__main__':
    if len(sys.argv) == 2:
        # Suppress output in our initial execution to establish a state.
        if sys.argv[1] == "--init":
            lib.global_vars.SUPPRESS_OUTPUT = True
    monitor_ssh_authorized_keys()

#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Monitor /etc/passwd for changes to detect malicious attempts to hijack/change users.

NOTE: The first execution of this script will only show you the current state of the environment which should be acknowledged before monitoring for changes will become an effective security measure.

Requirements:
None
"""

import os
from typing import Dict

from lib.state import load_state, store_state
from lib.util import output_error, output_finding
from lib.util_user import get_system_users

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.monitor_passwd import ACTIVATED
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))


def _get_passwd() -> Dict[str, str]:
    passwd_data = {}
    for user_obj in get_system_users():
        user = user_obj.name
        passwd_data[user] = str(user_obj)

    return passwd_data


def monitor_passwd():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    stored_passwd_data = {}
    try:
        stored_passwd_data = load_state(STATE_DIR)

    except Exception as e:
        output_error(__file__, str(e))
        return

    curr_passwd_data = {}
    try:
        curr_passwd_data = _get_passwd()

    except Exception as e:
        output_error(__file__, str(e))
        return

    # Compare stored data with current one.
    for stored_entry_user in stored_passwd_data.keys():

        # Extract current entry belonging to the same user.
        if stored_entry_user not in curr_passwd_data.keys():
            message = "User '%s' was deleted." % stored_entry_user

            output_finding(__file__, message)

            continue

        # Check entry was modified.
        if stored_passwd_data[stored_entry_user] != curr_passwd_data[stored_entry_user]:
            message = "Passwd entry for user '%s' was modified.\n\n" % stored_entry_user
            message += "Old entry: %s\n" % stored_passwd_data[stored_entry_user]
            message += "New entry: %s" % curr_passwd_data[stored_entry_user]

            output_finding(__file__, message)

    # Check new data was added.
    for curr_entry_user in curr_passwd_data.keys():
        if curr_entry_user not in stored_passwd_data.keys():
            message = "User '%s' was added.\n\n" % curr_entry_user
            message += "Entry: %s" % curr_passwd_data[curr_entry_user]

            output_finding(__file__, message)

    try:
        store_state(STATE_DIR, curr_passwd_data)

    except Exception as e:
        output_error(__file__, str(e))


if __name__ == '__main__':
    monitor_passwd()

#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Monitor /etc/crontab, /etc/cron.d/*, user specific crontab files and script files run by cron (e.g., script files in /etc/cron.hourly) for changes to detect attempts for attacker persistence.
Additionally, check if crontab entries and user specific crontab files belong to existing system users.

NOTE: The first execution of this script should be done with the argument "--init".
Otherwise, the script will only show you the current state of the environment since no state was established yet.
However, this assumes that the system is uncompromised during the initial execution.
Hence, if you are unsure this is the case you should verify the current state
before monitoring for changes will become an effective security measure.

Requirements:
None
"""

import hashlib
import os
import re
import sys
from typing import Dict, List, Set

import lib.global_vars
from lib.state import load_state, store_state
from lib.util import output_error, output_finding
from lib.util_user import get_system_users

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.monitor_cron import ACTIVATED, USER_CRONTAB_DIR, CRON_SCRIPT_DIRS
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))
    USER_CRONTAB_DIR = "/var/spool/cron/crontabs/"
    CRON_SCRIPT_DIRS = ["/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly", "/etc/cron.d"]


def _calculate_hash(file_location: str) -> str:
    with open(file_location, "rb") as fp:
        file_hash = hashlib.md5()
        chunk = fp.read(1048576)
        while chunk:
            file_hash.update(chunk)
            chunk = fp.read(1048576)

    return file_hash.hexdigest().upper()


def _get_cron_script_files() -> Dict[str, str]:
    cron_script_files = dict()
    for cron_script_dir in CRON_SCRIPT_DIRS:
        for cron_script_file in os.listdir(cron_script_dir):
            cron_script_location = os.path.join(cron_script_dir, cron_script_file)
            cron_script_files[cron_script_location] = _calculate_hash(cron_script_location)

    return cron_script_files


def _get_crontab_files() -> Dict[str, List[str]]:
    crontab_entries = dict()

    # Add default location of crontab entries.
    crontab_files = ["/etc/crontab"]

    # Add crontab files that are installed by other software.
    for crond_file in os.listdir("/etc/cron.d"):
        crond_location = os.path.join("/etc/cron.d", crond_file)
        if os.path.isfile(crond_location):
            crontab_files.append(crond_location)

    # Add user individual crontab files.
    for crontab_file in os.listdir(USER_CRONTAB_DIR):
        crontab_location = os.path.join(USER_CRONTAB_DIR, crontab_file)
        if os.path.isfile(crontab_location):
            crontab_files.append(crontab_location)

    for crontab_file in crontab_files:
        crontab_entries[crontab_file] = _parse_crontab(crontab_file)

    return crontab_entries


def _get_crontab_users(curr_crontab_data: Dict[str, List[str]]) -> Set[str]:
    crontab_users = set()

    # User individual crontab files are named after the username.
    for crontab_file in os.listdir(USER_CRONTAB_DIR):
        crontab_users.add(crontab_file)

    # Extract all crontab entries that contain a user that should run the command.
    crontab_entries_with_user = list(curr_crontab_data["/etc/crontab"])
    for crontab_file in curr_crontab_data.keys():
        if crontab_file.startswith("/etc/cron.d/"):
            crontab_entries_with_user.extend(curr_crontab_data[crontab_file])

    # Extract user from crontab entries.
    for crontab_entry in crontab_entries_with_user:
        match = re.fullmatch(r'([*?\-,/\d]+)\s([*?\-,/\d]+)\s([*?\-,/\dLW]+)\s([*?\-,/\d]+)\s([*?\-,/\dL#]+)\s([\-\w]+)\s+(.+)',
                             crontab_entry)
        if match is not None:
            crontab_users.add(match.groups()[5])

    return crontab_users


def _parse_crontab(file_location: str) -> List[str]:
    entries = list()
    with open(file_location, 'rt') as fp:
        for line in fp:
            line_strip = line.strip()
            if line_strip == "" or line_strip[0] == "#":
                continue

            entries.append(line_strip)

    return entries


def monitor_cron():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    stored_cron_data = {}
    try:
        stored_cron_data = load_state(STATE_DIR)

    except Exception as e:
        output_error(__file__, str(e))
        return

    # Add crontab key in case we do not have any stored data yet.
    if "crontab" not in stored_cron_data.keys():
        stored_cron_data["crontab"] = {}

    # Add cronscripts key in case we do not have any stored data yet.
    if "cronscripts" not in stored_cron_data.keys():
        stored_cron_data["cronscripts"] = {}

    curr_crontab_data = {}
    try:
        curr_crontab_data = _get_crontab_files()

    except Exception as e:
        output_error(__file__, str(e))
        return

    # Compare stored crontab data with current one.
    stored_crontab_data = stored_cron_data["crontab"]
    for stored_crontab_file, stored_crontab_entries in stored_crontab_data.items():

        # Check if crontab file was deleted.
        if stored_crontab_file not in curr_crontab_data.keys():
            message = "Crontab file '%s' was deleted." % stored_crontab_file
            output_finding(__file__, message)
            continue

        # Check entries were deleted.
        for stored_crontab_entry in stored_crontab_entries:
            if stored_crontab_entry not in curr_crontab_data[stored_crontab_file]:
                message = "Entry in crontab file '%s' was deleted.\n\n" % stored_crontab_file
                message += "Deleted entry: %s" % stored_crontab_entry
                output_finding(__file__, message)

        # Check entries were added.
        for curr_crontab_entry in curr_crontab_data[stored_crontab_file]:
            if curr_crontab_entry not in stored_crontab_entries:
                message = "Entry in crontab file '%s' was added.\n\n" % stored_crontab_file
                message += "Added entry: %s" % curr_crontab_entry
                output_finding(__file__, message)

    # Check new crontab file added.
    for curr_crontab_file, curr_crontab_entries in curr_crontab_data.items():
        if curr_crontab_file not in stored_crontab_data.keys():
            message = "Crontab file '%s' was added.\n\n" % curr_crontab_file
            for curr_crontab_entry in curr_crontab_entries:
                message += "Entry: %s\n" % curr_crontab_entry
            output_finding(__file__, message)

    # Check users running crontab entries actually exist as system users.
    system_users = get_system_users()
    for crontab_user in _get_crontab_users(curr_crontab_data):
        if not any([crontab_user == x.name for x in system_users]):
            message = "Crontab entry or entries are run as user '%s' but no such system user exists." % crontab_user
            output_finding(__file__, message)

    curr_script_data = {}
    try:
        curr_script_data = _get_cron_script_files()

    except Exception as e:
        output_error(__file__, str(e))
        return

    # Compare stored cron script data with current one.
    stored_script_data = stored_cron_data["cronscripts"]
    for stored_script_file, stored_script_hash in stored_script_data.items():

        # Check if cron script file was deleted.
        if stored_script_file not in curr_script_data.keys():
            message = "Cron script file '%s' was deleted." % stored_script_file
            output_finding(__file__, message)
            continue

        # Check if cron script file was modified.
        if stored_script_hash != curr_script_data[stored_script_file]:
            message = "Cron script file '%s' was modified." % stored_script_file
            output_finding(__file__, message)

    # Check new cron script file added.
    for curr_script_file in curr_script_data.keys():
        if curr_script_file not in stored_script_data.keys():
            message = "Cron script file '%s' was added." % curr_script_file
            output_finding(__file__, message)

    try:
        store_state(STATE_DIR, {"crontab": curr_crontab_data,
                                "cronscripts": curr_script_data})

    except Exception as e:
        output_error(__file__, str(e))


if __name__ == '__main__':
    if len(sys.argv) == 2:
        # Suppress output in our initial execution to establish a state.
        if sys.argv[1] == "--init":
            lib.global_vars.SUPPRESS_OUTPUT = True
    monitor_cron()

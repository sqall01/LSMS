#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Monitor systemd unit files to find ones that are used for malware persistence.

NOTE: The first execution of this script should be done with the argument "--init".
Otherwise, the script will only show you the current state of the environment since no state was established yet.
However, this assumes that the system is uncompromised during the initial execution.
Hence, if you are unsure this is the case you should verify the current state
before monitoring for changes will become an effective security measure.

Requirements:
None

Reference:
https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html
"""

import os
import sys
from typing import Dict

import lib.global_vars
from lib.state import load_state, store_state
from lib.util import get_diff_per_line, output_error, output_finding

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.monitor_systemd_units import ACTIVATED, SYSTEMD_UNIT_DIRS
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))
    SYSTEMD_UNIT_DIRS = ["/etc/systemd/system",
                         "/etc/systemd/user",
                         "/etc/systemd/network",
                         "/usr/lib/systemd/system",
                         "/usr/lib/systemd/user",
                         "/usr/lib/systemd/network",
                         "/usr/local/lib/systemd/system",
                         "/usr/local/lib/systemd/user",
                         "/usr/local/lib/systemd/network",
                         "/lib/systemd/system",
                         "/lib/systemd/user",
                         "/lib/systemd/network"]


def _get_system_unit_files() -> Dict[str, str]:
    systemd_unit_files = dict()
    for systemd_unit_dir in SYSTEMD_UNIT_DIRS:
        for root, _, files in os.walk(systemd_unit_dir):
            for file in files:
                file_location = os.path.join(root, file)

                # Some files are broken symlinks, hence, check if they exist
                if os.path.exists(file_location):
                    with open(file_location, "rt") as fp:
                        data = fp.read()

                    # Filter for systemd unit files that can execute commands
                    if "[Unit]" in data and "[Service]" in data:
                        # Since keys do not have to start at the beginning of the line, we go through each line,
                        # remove whitespaces leading whitespaces and check if it starts with a key we are interested in
                        for line in data.split("\n"):
                            normalized_line = line.strip()
                            if any(normalized_line.startswith(x) for x in ["ExecStart",
                                                                           "ExecStartPre",
                                                                           "ExecStartPost",
                                                                           "ExecReload",
                                                                           "ExecStop",
                                                                           "ExecStopPost"]):

                                # Store complete data of unit file. Even on a non-server system such as a
                                # xubuntu 22.04 we only have around 700 unit files of interest. Calculating with
                                # 1kB of data per file (which is way larger than a normal unit file has) we only
                                # need a little over 700 kB memory for this. Even on a Raspberry Pi we have no
                                # problem doing this. Further, it will prevent race-conditions when we already
                                # have the data stored and do not read it afterwards from the file if we generate
                                # alerts.
                                systemd_unit_files[file_location] = data
                                break

    return systemd_unit_files


def monitor_systemd_units():
    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    stored_systemd_units_data = {}
    try:
        stored_systemd_units_data = load_state(STATE_DIR)

    except Exception as e:
        output_error(__file__, str(e))
        return

    # Add units key in case we do not have any stored data yet.
    if "units" not in stored_systemd_units_data.keys():
        stored_systemd_units_data["units"] = {}

    curr_systemd_units_data = {}
    try:
        curr_systemd_units_data = _get_system_unit_files()

    except Exception as e:
        output_error(__file__, str(e))
        return

    # Compare stored unit files data with current one.
    stored_units_data = stored_systemd_units_data["units"]
    for stored_unit_file, stored_unit_data in stored_units_data.items():

        # Check if unit file was deleted.
        if stored_unit_file not in curr_systemd_units_data.keys():
            message = "Systemd unit file '%s' was deleted." % stored_unit_file
            output_finding(__file__, message)
            continue

        # Check if unit file was modified.
        if stored_unit_data != curr_systemd_units_data[stored_unit_file]:

            diff = get_diff_per_line("Old",
                                     stored_unit_data,
                                     "New",
                                     curr_systemd_units_data[stored_unit_file])

            message = "Systemd unit file '%s' was modified:\n\nDiff:\n%s\n\nNew file:\n%s" % (stored_unit_file,
                                                                                              diff,
                                                                                              curr_systemd_units_data[stored_unit_file])  # noqa:E501

            output_finding(__file__, message)

    # Check new unit file added.
    for curr_unit_file in curr_systemd_units_data.keys():
        if curr_unit_file not in stored_units_data.keys():
            message = "Systemd unit file '%s' was added:\n\n%s" % (curr_unit_file,
                                                                   curr_systemd_units_data[curr_unit_file])
            output_finding(__file__, message)

    try:
        store_state(STATE_DIR, {"units": curr_systemd_units_data})

    except Exception as e:
        output_error(__file__, str(e))


if __name__ == '__main__':
    if len(sys.argv) == 2:
        # Suppress output in our initial execution to establish a state.
        if sys.argv[1] == "--init":
            lib.global_vars.SUPPRESS_OUTPUT = True
    monitor_systemd_units()

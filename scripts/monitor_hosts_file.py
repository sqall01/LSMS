#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Monitor /etc/hosts for changes to detect malicious attempts to divert traffic.

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
from typing import Dict, Set

import lib.global_vars
from lib.state import load_state, store_state
from lib.util import output_error, output_finding

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.monitor_hosts_file import ACTIVATED
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))


class MonitorHostsException(Exception):
    pass


def _get_hosts() -> Dict[str, Set[str]]:

    hosts_data = {}
    with open("/etc/hosts", 'rt') as fp:
        for line in fp:
            line = line.strip()

            if line == "":
                continue

            # Ignore comments.
            if line[0] == "#":
                continue

            entry = line.split()
            if len(entry) < 2:
                raise MonitorHostsException("Not able to parse line: %s" % line)

            ip = entry[0]
            hosts = set(entry[1:])
            if ip not in hosts_data.keys():
                hosts_data[ip] = hosts

            else:
                for host in hosts:
                    hosts_data[ip].add(host)

    return hosts_data


def monitor_hosts():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    stored_hosts_data = {}
    try:
        state_data = load_state(STATE_DIR)

        # Convert list to set.
        for k, v in state_data.items():
            stored_hosts_data[k] = set(v)

    except Exception as e:
        output_error(__file__, str(e))
        return

    curr_hosts_data = {}
    try:
        curr_hosts_data = _get_hosts()

    except Exception as e:
        output_error(__file__, str(e))
        return

    # Compare stored data with current one.
    for stored_entry_ip in stored_hosts_data.keys():

        # Extract current entry belonging to the same ip.
        if stored_entry_ip not in curr_hosts_data.keys():
            message = "Host name for IP '%s' was deleted." % stored_entry_ip

            output_finding(__file__, message)

            continue

        # Check host entry was removed.
        for host in stored_hosts_data[stored_entry_ip]:
            if host not in curr_hosts_data[stored_entry_ip]:
                message = "Host name entry for IP '%s' was removed.\n\n" % stored_entry_ip
                message += "Entry: %s" % host

                output_finding(__file__, message)

        # Check host entry was added.
        for host in curr_hosts_data[stored_entry_ip]:
            if host not in stored_hosts_data[stored_entry_ip]:
                message = "Host name entry for IP '%s' was added.\n\n" % stored_entry_ip
                message += "Entry: %s" % host

                output_finding(__file__, message)

    # Check new data was added.
    for curr_entry_ip in curr_hosts_data.keys():
        if curr_entry_ip not in stored_hosts_data.keys():
            message = "New host name was added for IP '%s'.\n\n" % curr_entry_ip
            message += "Entries:\n"
            for host in curr_hosts_data[curr_entry_ip]:
                message += host
                message += "\n"

            output_finding(__file__, message)

    try:
        # Convert set to list.
        state_data = {}
        for k, v in curr_hosts_data.items():
            state_data[k] = list(v)

        store_state(STATE_DIR, state_data)

    except Exception as e:
        output_error(__file__, str(e))


if __name__ == '__main__':
    if len(sys.argv) == 2:
        # Suppress output in our initial execution to establish a state.
        if sys.argv[1] == "--init":
            lib.global_vars.SUPPRESS_OUTPUT = True
    monitor_hosts()

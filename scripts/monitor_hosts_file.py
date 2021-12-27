#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# # Licensed under the MIT License.

"""
Short summary:
Monitor /etc/hosts for changes to detect malicious attempts to divert traffic.

Requirements:
None
"""

import os
import json
import socket
import stat
from typing import Dict, Set

from lib.alerts import raise_alert_alertr, raise_alert_mail

# Read configuration and library functions.
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

MAIL_SUBJECT = "[Security] Monitoring /etc/hosts on host '%s'" % socket.gethostname()


class MonitorHostsException(Exception):
    def __init__(self, msg: str):
        self._msg = msg

    def __str__(self):
        return self._msg


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


def _load_hosts_data() -> Dict[str, Set[str]]:
    state_file = os.path.join(STATE_DIR, "state")
    hosts_data = {}
    if os.path.isfile(state_file):
        data = None
        try:
            with open(state_file, 'rt') as fp:
                data = fp.read()
            if data is None:
                raise MonitorHostsException("Read state data is None.")

            temp = json.loads(data)

            # Convert list to set.
            for k,v in temp.items():
                hosts_data[k] = set(v)

        except Exception as e:
            raise MonitorHostsException("State data: '%s'; Exception: '%s'" % (str(data), str(e)))

    return hosts_data


def _output_error(msg: str):

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if print_output:
        print(msg)

    else:
        hostname = socket.gethostname()
        message = "Error monitoring /etc/hosts on host '%s': %s" \
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


def _store_hosts_data(hosts_data: Dict[str, Set[str]]):
    # Create state dir if it does not exist.
    if not os.path.exists(STATE_DIR):
        os.makedirs(STATE_DIR)

    state_file = os.path.join(STATE_DIR, "state")

    # Convert set to list.
    temp = {}
    for k, v in hosts_data.items():
        temp[k] = list(v)

    with open(state_file, 'wt') as fp:
        fp.write(json.dumps(temp))

    os.chmod(state_file, stat.S_IREAD | stat.S_IWRITE)


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
        stored_hosts_data =_load_hosts_data()

    except Exception as e:
        _output_error(str(e))
        return

    curr_hosts_data = {}
    try:
        curr_hosts_data = _get_hosts()

    except Exception as e:
        _output_error(str(e))
        return

    # Compare stored data with current one.
    for stored_entry_ip in stored_hosts_data.keys():

        # Extract current entry belonging to the same ip.
        if stored_entry_ip not in curr_hosts_data.keys():
            hostname = socket.gethostname()
            message = "Host name for IP '%s' was deleted on host '%s'." \
                      % (stored_entry_ip, hostname)

            if print_output:
                print(message)
                print("#" * 80)

            if ALERTR_FIFO:
                optional_data = dict()
                optional_data["ip"] = stored_entry_ip
                optional_data["hostname"] = hostname
                optional_data["message"] = message

                raise_alert_alertr(ALERTR_FIFO,
                                   optional_data)

            if FROM_ADDR is not None and TO_ADDR is not None:
                raise_alert_mail(FROM_ADDR,
                                 TO_ADDR,
                                 MAIL_SUBJECT,
                                 message)

            continue

        # Check host entry was removed.
        for host in stored_hosts_data[stored_entry_ip]:
            if host not in curr_hosts_data[stored_entry_ip]:
                hostname = socket.gethostname()
                message = "Host name entry for IP '%s' was removed on host '%s'.\n\n" % (stored_entry_ip, hostname)
                message += "Entry: %s" % host

                if print_output:
                    print(message)
                    print("#" * 80)

                if ALERTR_FIFO:
                    optional_data = dict()
                    optional_data["ip"] = stored_entry_ip
                    optional_data["host_entry"] = host
                    optional_data["hostname"] = hostname
                    optional_data["message"] = message

                    raise_alert_alertr(ALERTR_FIFO,
                                       optional_data)

                if FROM_ADDR is not None and TO_ADDR is not None:
                    raise_alert_mail(FROM_ADDR,
                                     TO_ADDR,
                                     MAIL_SUBJECT,
                                     message)

        # Check host entry was added.
        for host in curr_hosts_data[stored_entry_ip]:
            if host not in stored_hosts_data[stored_entry_ip]:
                hostname = socket.gethostname()
                message = "Host name entry for IP '%s' was added on host '%s'.\n\n" % (stored_entry_ip, hostname)
                message += "Entry: %s" % host

                if print_output:
                    print(message)
                    print("#" * 80)

                if ALERTR_FIFO:
                    optional_data = dict()
                    optional_data["ip"] = stored_entry_ip
                    optional_data["host_entry"] = host
                    optional_data["hostname"] = hostname
                    optional_data["message"] = message

                    raise_alert_alertr(ALERTR_FIFO,
                                       optional_data)

                if FROM_ADDR is not None and TO_ADDR is not None:
                    raise_alert_mail(FROM_ADDR,
                                     TO_ADDR,
                                     MAIL_SUBJECT,
                                     message)

    # Check new data was added.
    for curr_entry_ip in curr_hosts_data.keys():
        if curr_entry_ip not in stored_hosts_data.keys():
            hostname = socket.gethostname()
            message = "New host name was added for IP '%s' on host '%s'.\n\n" \
                      % (curr_entry_ip, hostname)
            message += "Entries:\n"
            for host in curr_hosts_data[curr_entry_ip]:
                message += host
                message += "\n"

            if print_output:
                print(message)
                print("#" * 80)

            if ALERTR_FIFO:
                optional_data = dict()
                optional_data["ip"] = curr_entry_ip
                optional_data["hosts"] = list(curr_hosts_data[curr_entry_ip])
                optional_data["hostname"] = hostname
                optional_data["message"] = message

                raise_alert_alertr(ALERTR_FIFO,
                                   optional_data)

            if FROM_ADDR is not None and TO_ADDR is not None:
                raise_alert_mail(FROM_ADDR,
                                 TO_ADDR,
                                 MAIL_SUBJECT,
                                 message)

    try:
        _store_hosts_data(curr_hosts_data)

    except Exception as e:
        _output_error(str(e))


if __name__ == '__main__':
    monitor_hosts()

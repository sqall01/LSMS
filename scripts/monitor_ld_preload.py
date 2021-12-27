#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# # Licensed under the MIT License.

"""
Short summary:
Monitor /etc/ld.so.preload for changes to detect malicious attempts to alter the control flow of binaries.

Requirements:
None
"""

import os
import json
import socket
import stat
from typing import Set

from lib.alerts import raise_alert_alertr, raise_alert_mail

# Read configuration and library functions.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR
    from config.monitor_ld_preload import ACTIVATED
    STATE_DIR = os.path.join(os.path.dirname(__file__), STATE_DIR, os.path.basename(__file__))
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True
    STATE_DIR = os.path.join("/tmp", os.path.basename(__file__))

MAIL_SUBJECT = "[Security] Monitoring /etc/ld.so.preload on host '%s'" % socket.gethostname()


class MonitorLdPreloadException(Exception):
    def __init__(self, msg: str):
        self._msg = msg

    def __str__(self):
        return self._msg


def _get_ld_preload() -> Set[str]:
    path = "/etc/ld.so.preload"
    ld_data = set()
    if os.path.isfile(path):
        with open(path, 'rt') as fp:
            for line in fp:

                if line.strip() == "":
                    continue

                ld_data.add(line.strip())

    return ld_data


def _load_ld_preload_data() -> Set[str]:
    state_file = os.path.join(STATE_DIR, "state")
    ld_data = set()
    if os.path.isfile(state_file):
        data = None
        try:
            with open(state_file, 'rt') as fp:
                data = fp.read()
            if data is None:
                raise MonitorLdPreloadException("Read state data is None.")

            temp = json.loads(data)
            ld_data = set(temp)

        except Exception as e:
            raise MonitorLdPreloadException("State data: '%s'; Exception: '%s'" % (str(data), str(e)))

    return ld_data


def _output_error(msg: str):

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if print_output:
        print(msg)

    else:
        hostname = socket.gethostname()
        message = "Error monitoring /etc/ld.so.preload on host '%s': %s" \
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


def _store_ld_preload_data(ld_data: Set[str]):
    # Create state dir if it does not exist.
    if not os.path.exists(STATE_DIR):
        os.makedirs(STATE_DIR)

    state_file = os.path.join(STATE_DIR, "state")

    # Convert set to list.
    temp = list(ld_data)

    with open(state_file, 'wt') as fp:
        fp.write(json.dumps(temp))

    os.chmod(state_file, stat.S_IREAD | stat.S_IWRITE)


def monitor_ld_preload():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    stored_ld_data = set()
    try:
        stored_ld_data =_load_ld_preload_data()

    except Exception as e:
        _output_error(str(e))
        return

    curr_ld_data = set()
    try:
        curr_ld_data = _get_ld_preload()

    except Exception as e:
        _output_error(str(e))
        return

    # Compare stored data with current one.
    for stored_entry in stored_ld_data:
        if stored_entry not in curr_ld_data:
            hostname = socket.gethostname()
            message = "LD_PRELOAD entry '%s' was deleted on host '%s'." \
                      % (stored_entry, hostname)

            if print_output:
                print(message)

            if ALERTR_FIFO:
                optional_data = dict()
                optional_data["entry"] = stored_entry
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

    # Check new data was added.
    for curr_entry in curr_ld_data:
        if curr_entry not in stored_ld_data:
            hostname = socket.gethostname()
            message = "LD_PRELOAD entry '%s' was added on host '%s'.\n\n" \
                      % (curr_entry, hostname)

            if print_output:
                print(message)

            if ALERTR_FIFO:
                optional_data = dict()
                optional_data["entry"] = curr_entry
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
        _store_ld_preload_data(curr_ld_data)

    except Exception as e:
        _output_error(str(e))


if __name__ == '__main__':
    monitor_ld_preload()

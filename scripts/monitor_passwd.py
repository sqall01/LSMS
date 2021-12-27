#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# # Licensed under the MIT License.

"""
Short summary:
Monitor /etc/passwd for changes to detect malicious attempts to hijack/change users.

Requirements:
None
"""

import os
import json
import socket
import stat
from typing import Dict

from lib.alerts import raise_alert_alertr, raise_alert_mail

# Read configuration and library functions.
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

MAIL_SUBJECT = "[Security] Monitoring /etc/passwd on host '%s'" % socket.gethostname()


class MonitorPasswdException(Exception):
    def __init__(self, msg: str):
        self._msg = msg

    def __str__(self):
        return self._msg


def _get_passwd() -> Dict[str, str]:

    passwd_data = {}
    with open("/etc/passwd", 'rt') as fp:
        for line in fp:
            line = line.strip()

            if line == "":
                continue

            entry = line.strip().split(":")

            user = entry[0]
            passwd_data[user] = line

    return passwd_data


def _load_passwd_data() -> Dict[str, str]:
    state_file = os.path.join(STATE_DIR, "state")
    passwd_data = {}
    if os.path.isfile(state_file):
        data = None
        try:
            with open(state_file, 'rt') as fp:
                data = fp.read()
            if data is None:
                raise MonitorPasswdException("Read state data is None.")

            passwd_data = json.loads(data)

        except Exception as e:
            raise MonitorPasswdException("State data: '%s'; Exception: '%s'" % (str(data), str(e)))

    return passwd_data


def _output_error(msg: str):

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if print_output:
        print(msg)

    else:
        hostname = socket.gethostname()
        message = "Error monitoring /etc/passwd on host '%s': %s" \
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


def _store_passwd_data(passwd_data: Dict[str, str]):
    # Create state dir if it does not exist.
    if not os.path.exists(STATE_DIR):
        os.makedirs(STATE_DIR)

    state_file = os.path.join(STATE_DIR, "state")

    with open(state_file, 'wt') as fp:
        fp.write(json.dumps(passwd_data))

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

    stored_passwd_data = {}
    try:
        stored_passwd_data =_load_passwd_data()

    except Exception as e:
        _output_error(str(e))
        return

    curr_passwd_data = {}
    try:
        curr_passwd_data = _get_passwd()

    except Exception as e:
        _output_error(str(e))
        return

    # Compare stored data with current one.
    for stored_entry_user in stored_passwd_data.keys():

        # Extract current entry belonging to the same user.
        if stored_entry_user not in curr_passwd_data.keys():
            hostname = socket.gethostname()
            message = "User '%s' was deleted on host '%s'." \
                      % (stored_entry_user, hostname)

            if print_output:
                print(message)
                print("#" * 80)

            if ALERTR_FIFO:
                optional_data = dict()
                optional_data["user"] = stored_entry_user
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

        # Check entry was modified.
        if stored_passwd_data[stored_entry_user] != curr_passwd_data[stored_entry_user]:
            hostname = socket.gethostname()
            message = "Passwd entry for user '%s' was modified on host '%s'.\n\n" % (stored_entry_user, hostname)
            message += "Old entry: %s\n" % stored_passwd_data[stored_entry_user]
            message += "New entry: %s" % curr_passwd_data[stored_entry_user]

            if print_output:
                print(message)
                print("#" * 80)

            if ALERTR_FIFO:
                optional_data = dict()
                optional_data["user"] = stored_entry_user
                optional_data["old_entry"] = stored_passwd_data[stored_entry_user]
                optional_data["new_entry"] = curr_passwd_data[stored_entry_user]
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
    for curr_entry_user in curr_passwd_data.keys():
        if curr_entry_user not in stored_passwd_data.keys():
            hostname = socket.gethostname()
            message = "User '%s' was added on host '%s'.\n\n" \
                      % (curr_entry_user, hostname)
            message += "Entry: %s" % curr_passwd_data[curr_entry_user]

            if print_output:
                print(message)
                print("#"*80)

            if ALERTR_FIFO:
                optional_data = dict()
                optional_data["user"] = curr_entry_user
                optional_data["entry"] = curr_passwd_data[curr_entry_user]
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
        _store_passwd_data(curr_passwd_data)

    except Exception as e:
        _output_error(str(e))


if __name__ == '__main__':
    monitor_hosts()

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

Requirements:
None
"""

import os
import json
import stat
import socket
from typing import List, Tuple, Dict, Any

from lib.alerts import raise_alert_alertr, raise_alert_mail

# Read configuration and library functions.
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

MAIL_SUBJECT = "[Security] Monitoring SSH authorized_keys on host '%s'" % socket.gethostname()


class MonitorSSHException(Exception):
    def __init__(self, msg: str):
        self._msg = msg

    def __str__(self):
        return self._msg


def _get_home_dirs_from_passwd() -> List[Tuple[str, str]]:
    user_home_list = []
    try:
        with open("/etc/passwd", 'rt') as fp:
            for line in fp:
                line_split = line.split(":")
                user_home_list.append((line_split[0], line_split[5]))

    except Exception as e:
        raise MonitorSSHException(str(e))

    return user_home_list


def _get_system_ssh_data() -> List[Dict[str, Any]]:
    ssh_data = []
    user_home_list = _get_home_dirs_from_passwd()

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


def _load_ssh_data() -> List[Dict[str, Any]]:
    state_file = os.path.join(STATE_DIR, "state")
    ssh_data = []
    if os.path.isfile(state_file):
        data = None
        try:
            with open(state_file, 'rt') as fp:
                data = fp.read()
            if data is None:
                raise MonitorSSHException("Read state data is None.")

            ssh_data = json.loads(data)

        except Exception as e:
            raise MonitorSSHException("State data: '%s'; Exception: '%s'" % (str(data), str(e)))

    return ssh_data


def _output_error(msg: str):

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if print_output:
        print(msg)

    else:
        hostname = socket.gethostname()
        message = "Error monitoring SSH authorized_keys on host '%s': %s" \
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


def _parse_authorized_keys_file(authorized_keys_file: str) -> List[str]:
    entries = set()
    try:
        with open(authorized_keys_file, 'rt') as fp:
            for line in fp:
                entries.add(line.strip())

    except Exception as e:
        raise MonitorSSHException("Unable to parse file '%s'; Exception: '%s'" % (authorized_keys_file, str(e)))

    return list(entries)


def _store_ssh_data(ssh_data: List[Dict[str, Any]]):
    # Create state dir if it does not exist.
    if not os.path.exists(STATE_DIR):
        os.makedirs(STATE_DIR)

    state_file = os.path.join(STATE_DIR, "state")
    with open(state_file, 'wt') as fp:
        fp.write(json.dumps(ssh_data))

    os.chmod(state_file, stat.S_IREAD | stat.S_IWRITE)


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
        stored_ssh_data = _load_ssh_data()
        curr_ssh_data = _get_system_ssh_data()

    except Exception as e:
        _output_error(str(e))
        return

    # Check if any authorized_keys file is world writable.
    for curr_entry in curr_ssh_data:
        authorized_keys_file = curr_entry["authorized_keys_file"]
        file_stat = os.stat(authorized_keys_file)
        if file_stat.st_mode & stat.S_IWOTH:
            hostname = socket.gethostname()
            message = "SSH authorized_keys file for user '%s' is world writable on host '%s'." \
                      % (curr_entry["user"], hostname)

            if print_output:
                print(message)
                print("#" * 80)

            if ALERTR_FIFO:
                optional_data = dict()
                optional_data["username"] = curr_entry["user"]
                optional_data["hostname"] = hostname
                optional_data["message"] = message

                raise_alert_alertr(ALERTR_FIFO,
                                   optional_data)

            if FROM_ADDR is not None and TO_ADDR is not None:
                raise_alert_mail(FROM_ADDR,
                                 TO_ADDR,
                                 MAIL_SUBJECT,
                                 message)

    # Compare stored data with current one.
    for stored_entry in stored_ssh_data:

        # Extract current entry belonging to the same user.
        curr_user_entry = None
        for curr_entry in curr_ssh_data:
            if stored_entry["user"] == curr_entry["user"]:
                curr_user_entry = curr_entry
                break
        if curr_user_entry is None:
            hostname = socket.gethostname()
            message = "SSH authorized_keys file for user '%s' was deleted on host '%s'." \
                      % (stored_entry["user"], hostname)

            if print_output:
                print(message)
                print("#" * 80)

            if ALERTR_FIFO:
                optional_data = dict()
                optional_data["username"] = stored_entry["user"]
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

        # Check authorized_keys path has changed.
        if stored_entry["authorized_keys_file"] != curr_user_entry["authorized_keys_file"]:
            hostname = socket.gethostname()
            message = "SSH authorized_keys location for user '%s' changed from '%s' to '%s' on host '%s'." \
                      % (stored_entry["user"],
                         stored_entry["authorized_keys_file"],
                         curr_user_entry["authorized_keys_file"],
                         hostname)

            if print_output:
                print(message)
                print("#" * 80)

            if ALERTR_FIFO:
                optional_data = dict()
                optional_data["username"] = stored_entry["user"]
                optional_data["from"] = stored_entry["authorized_keys_file"]
                optional_data["to"] = curr_user_entry["authorized_keys_file"]
                optional_data["hostname"] = hostname
                optional_data["message"] = message

                raise_alert_alertr(ALERTR_FIFO,
                                   optional_data)

            if FROM_ADDR is not None and TO_ADDR is not None:
                raise_alert_mail(FROM_ADDR,
                                 TO_ADDR,
                                 MAIL_SUBJECT,
                                 message)

        # Check authorized_key was removed.
        for authorized_key in stored_entry["authorized_keys_entries"]:
            if authorized_key not in curr_user_entry["authorized_keys_entries"]:
                hostname = socket.gethostname()
                message = "SSH authorized_keys entry was removed on host '%s'.\n\n" % hostname
                message += "Entry: %s" % authorized_key

                if print_output:
                    print(message)
                    print("#" * 80)

                if ALERTR_FIFO:
                    optional_data = dict()
                    optional_data["username"] = stored_entry["user"]
                    optional_data["authorized_keys_entry"] = authorized_key
                    optional_data["hostname"] = hostname
                    optional_data["message"] = message

                    raise_alert_alertr(ALERTR_FIFO,
                                       optional_data)

                if FROM_ADDR is not None and TO_ADDR is not None:
                    raise_alert_mail(FROM_ADDR,
                                     TO_ADDR,
                                     MAIL_SUBJECT,
                                     message)

        # Check authorized_key was added.
        for authorized_key in curr_user_entry["authorized_keys_entries"]:
            if authorized_key not in stored_entry["authorized_keys_entries"]:
                hostname = socket.gethostname()
                message = "SSH authorized_keys entry was added on host '%s'.\n\n" % hostname
                message += "Entry: %s" % authorized_key

                if print_output:
                    print(message)
                    print("#" * 80)

                if ALERTR_FIFO:
                    optional_data = dict()
                    optional_data["username"] = stored_entry["user"]
                    optional_data["authorized_keys_entry"] = authorized_key
                    optional_data["hostname"] = hostname
                    optional_data["message"] = message

                    raise_alert_alertr(ALERTR_FIFO,
                                       optional_data)

                if FROM_ADDR is not None and TO_ADDR is not None:
                    raise_alert_mail(FROM_ADDR,
                                     TO_ADDR,
                                     MAIL_SUBJECT,
                                     message)

    for curr_entry in curr_ssh_data:
        found = False
        for stored_entry in stored_ssh_data:
            if curr_entry["user"] == stored_entry["user"]:
                found = True
                break
        if not found:
            hostname = socket.gethostname()
            message = "New authorized_keys file was added for user '%s' on host '%s'.\n\n" \
                      % (curr_entry["user"], hostname)
            message += "Entries:\n"
            for authorized_key in curr_entry["authorized_keys_entries"]:
                message += authorized_key
                message += "\n"

            if print_output:
                print(message)
                print("#" * 80)

            if ALERTR_FIFO:
                optional_data = dict()
                optional_data["username"] = curr_entry["user"]
                optional_data["authorized_keys_entries"] = curr_entry["authorized_keys_entries"]
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
        _store_ssh_data(curr_ssh_data)

    except Exception as e:
        _output_error(str(e))


if __name__ == '__main__':
    monitor_ssh_authorized_keys()







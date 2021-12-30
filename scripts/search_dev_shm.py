#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Search for binaries and scripts in /dev/shm.
Malware that tries to hide is often stored there.

Requirements:
None

Reference:
https://twitter.com/CraigHRowland/status/1268863172825346050?s=20
https://twitter.com/CraigHRowland/status/1269196509079166976
"""

import os
import socket

# Read configuration and library functions.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR
    from config.search_dev_shm import ACTIVATED
    from lib.alerts import raise_alert_alertr, raise_alert_mail
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True


def search_suspicious_files():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    # Get all suspicious ELF files.
    fd = os.popen("find /dev/shm -type f -exec file -p '{}' \\; | grep ELF")
    elf_raw = fd.read().strip()
    fd.close()

    # Get all suspicious script files.
    fd = os.popen("find /dev/shm -type f -exec file -p '{}' \\; | grep script")
    script_raw = fd.read().strip()
    fd.close()

    suspicious_files = []
    if elf_raw.strip():
        suspicious_files.extend(elf_raw.strip().split("\n"))
    if script_raw.strip():
        suspicious_files.extend(script_raw.strip().split("\n"))

    for suspicious_file in suspicious_files:

        if print_output:
            print("SUSPICIOUS")
            print(suspicious_file)
            print("")

        else:
            if ALERTR_FIFO is not None:

                hostname = socket.gethostname()
                optional_data = dict()
                optional_data["suspicious_file"] = suspicious_file
                optional_data["hostname"] = hostname
                message = "File in /dev/shm on host '%s' suspicious.\n\n" % hostname
                message += suspicious_file
                optional_data["message"] = message

                raise_alert_alertr(ALERTR_FIFO,
                                   optional_data)

            if FROM_ADDR is not None and TO_ADDR is not None:

                hostname = socket.gethostname()
                subject = "[Security] Suspicious file found on '%s'" % hostname
                message = "File in /dev/shm on host '%s' suspicious.\n\n" % hostname
                message += suspicious_file

                raise_alert_mail(FROM_ADDR,
                                 TO_ADDR,
                                 subject,
                                 message)


if __name__ == '__main__':
    search_suspicious_files()

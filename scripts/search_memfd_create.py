#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# # Licensed under the MIT License.

"""
Short summary:
Malware uses calls such as memfd_create() to create an anonymous file in RAM that can be run.

Requirements:
None

Reference:
https://www.sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/
"""

import os
import socket

# Read configuration and library functions.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR
    from config.search_memfd_create import ACTIVATED
    from lib.alerts import raise_alert_alertr, raise_alert_mail
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = True


def search_deleted_memfd_files():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    # Get all suspicious ELF files.
    fd = os.popen("ls -laR /proc/*/exe 2> /dev/null | grep memfd:.*\(deleted\)")
    suspicious_exe_raw = fd.read().strip()
    fd.close()

    suspicious_exes = []
    if suspicious_exe_raw.strip():
        suspicious_exes.extend(suspicious_exe_raw.strip().split("\n"))

    for suspicious_exe in suspicious_exes:

        if print_output:
            print("SUSPICIOUS")
            print(suspicious_exe)
            print("")

        else:
            if ALERTR_FIFO is not None:

                hostname = socket.gethostname()
                optional_data = dict()
                optional_data["suspicious_exe"] = suspicious_exe
                optional_data["hostname"] = hostname
                message = "Deleted memfd file on host '%s' found.\n\n" % hostname
                message += suspicious_exe
                optional_data["message"] = message

                raise_alert_alertr(ALERTR_FIFO,
                                   optional_data)

            if FROM_ADDR is not None and TO_ADDR is not None:

                hostname = socket.gethostname()
                subject = "[Security] Deleted memfd file on '%s'" % hostname
                message = "Deleted memfd file on host '%s' found.\n\n" % hostname
                message += suspicious_exe

                raise_alert_mail(FROM_ADDR,
                                 TO_ADDR,
                                 subject,
                                 message)


if __name__ == '__main__':
    search_deleted_memfd_files()

#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
Malware will name itself with [brackets] to impersonate a Linux kernel thread.
Any Linux process that looks like a [kernel thread] should have an empty maps file.

Site note:
when using ps auxwf | grep "\[" they are children of [kthreadd]

Requirements:
None

Reference:
https://twitter.com/CraigHRowland/status/1232399132632813568
https://www.sandflysecurity.com/blog/detecting-linux-kernel-process-masquerading-with-command-line-forensics/
"""

import os
import socket

# Read configuration and library functions.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR
    from config.search_non_kthreads import NON_KTHREAD_WHITELIST, ACTIVATED
    from lib.alerts import raise_alert_alertr, raise_alert_mail
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    NON_KTHREAD_WHITELIST = []
    ACTIVATED = True


def search_suspicious_process():

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if not ACTIVATED:
        if print_output:
            print("Module deactivated.")
        return

    # Iterate over all processes that have a "[".
    fd = os.popen("ps auxw | grep \\\\[ | awk '{print $2}'")
    pids_raw = fd.read().strip()
    fd.close()
    for pid in pids_raw.split("\n"):

        # Get process name of pid.
        fd = os.popen("ps u -p %s" % pid)
        ps_output = fd.read().strip()
        fd.close()

        fd = os.popen("ps u -p %s | awk '{$1=$2=$3=$4=$5=$6=$7=$8=$9=$10=\"\"; print $0}'" % pid)
        process_name_raw = fd.read().strip()
        fd.close()
        for process_name in process_name_raw.split("\n"):
            process_name = process_name.strip()
            # Ignore COMMAND since it is part of the headline of ps output.
            if process_name == "COMMAND":
                continue

            # Check if we have whitelisted the process
            # (e.g., [lxc monitor] /var/lib/lxc satellite).
            elif process_name in NON_KTHREAD_WHITELIST:
                continue

            # Only consider process names that start with a "["
            # (e.g., "avahi-daemon: running [towelie.local]"" does not)
            elif process_name.startswith("["):

                if print_output:
                    print("Checking pid: %s (%s) - " % (pid, process_name),
                          end="")

                file_path = "/proc/%s/maps" % pid
                try:
                    with open(file_path, 'rt') as fp:
                        data = fp.read()
                        if data == "":
                            if print_output:
                                print("ok")
                            continue

                except Exception as e:
                    print("Exception")
                    print(e)
                    print("")
                    continue

                if print_output:
                    print("SUSPICIOUS")
                    print(ps_output)
                    print("")

                else:
                    if ALERTR_FIFO is not None:

                        hostname = socket.gethostname()
                        optional_data = dict()
                        optional_data["pid"] = pid
                        optional_data["ps_output"] = ps_output
                        optional_data["hostname"] = hostname
                        message = "Process with pid '%s' on host '%s' suspicious.\n\n" % (pid, hostname)
                        message += ps_output
                        optional_data["message"] = message

                        raise_alert_alertr(ALERTR_FIFO,
                                           optional_data)

                    if FROM_ADDR is not None and TO_ADDR is not None:

                        hostname = socket.gethostname()
                        subject = "[Security] Suspicious process found on '%s'" % hostname
                        message = "Process with pid '%s' on host '%s' suspicious.\n\n" % (pid, hostname)
                        message += ps_output

                        raise_alert_mail(FROM_ADDR,
                                         TO_ADDR,
                                         subject,
                                         message)


if __name__ == '__main__':
    search_suspicious_process()

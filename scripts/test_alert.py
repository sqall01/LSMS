#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# # Licensed under the MIT License.

"""
Short summary:
If scripts are executed via cronjob, this script helps to check if the alert functions work.

Requirements:
None
"""

import socket

# Read configuration and and library functions.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR
    from config.test_alert import ACTIVATED
    from lib.alerts import raise_alert_alertr, raise_alert_mail
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = False


if __name__ == '__main__':
    if ACTIVATED:
        if ALERTR_FIFO is not None:
            hostname = socket.gethostname()
            optional_data = dict()
            optional_data["hostname"] = hostname
            message = "Alert test on host '%s'." % hostname
            optional_data["message"] = message

            raise_alert_alertr(ALERTR_FIFO,
                               optional_data)

        if FROM_ADDR is not None and TO_ADDR is not None:
            hostname = socket.gethostname()
            subject = "[Security] Alert test on '%s'" % hostname
            message = "Alert test on host '%s'." % hostname

            raise_alert_mail(FROM_ADDR,
                             TO_ADDR,
                             subject,
                             message)

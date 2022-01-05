#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

"""
Short summary:
If scripts are executed via cronjob, this script helps to check if the alert functions work.

Requirements:
None
"""

from lib.util import output_finding

# Read configuration.
try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR
    from config.test_alert import ACTIVATED
except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None
    ACTIVATED = False


if __name__ == '__main__':
    if ACTIVATED:
        message = "Alert test."
        output_finding(__file__, message)

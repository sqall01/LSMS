import difflib
import os
import socket
import threading

from . import global_vars
from .alerts import raise_alert_alertr, raise_alert_mail

try:
    from config.config import ALERTR_FIFO, FROM_ADDR, TO_ADDR, STATE_DIR

except:
    ALERTR_FIFO = None
    FROM_ADDR = None
    TO_ADDR = None


def get_diff_per_line(name1: str, data1: str, name2: str, data2: str) -> str:
    # difflib function needs trailing newline for each element to build a usable output string
    temp1 = ["%s\n" % x for x in data1.split("\n")]
    temp2 = ["%s\n" % x for x in data2.split("\n")]
    return "".join(difflib.unified_diff(temp1, temp2, fromfile=name1, tofile=name2))


def output_error(file_name: str, msg: str):
    # Suppresses output, for example, if an initialization run is performed.
    if global_vars.SUPPRESS_OUTPUT:
        return

    base_name = os.path.basename(file_name)

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if print_output:
        message = "#" * 80
        message += "\nError in '%s':\n%s" % (base_name, msg)
        print(message)

    else:
        hostname = socket.gethostname()
        message = "Error in '%s' on host '%s':\n%s" \
                  % (base_name, hostname, msg)

        if ALERTR_FIFO:
            optional_data = dict()
            optional_data["error"] = True
            optional_data["script"] = base_name
            optional_data["message"] = message

            threading.Thread(target=raise_alert_alertr,
                             args=(ALERTR_FIFO, optional_data),
                             daemon=False).start()

        if FROM_ADDR is not None and TO_ADDR is not None:
            mail_subject = "[Security] Error in '%s' on host '%s'" % (base_name, socket.gethostname())
            threading.Thread(target=raise_alert_mail,
                             args=(FROM_ADDR, TO_ADDR, mail_subject, message),
                             daemon=False).start()


def output_finding(file_name: str, msg: str):
    # Suppresses output, for example, if an initialization run is performed.
    if global_vars.SUPPRESS_OUTPUT:
        return

    base_name = os.path.basename(file_name)

    # Decide where to output results.
    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    if print_output:
        message = "#" * 80
        message += "\nFinding in '%s':\n%s" % (base_name, msg)

        print(message)

    else:
        hostname = socket.gethostname()
        message = "Finding in '%s' on host '%s':\n%s" \
                  % (base_name, hostname, msg)

        if ALERTR_FIFO:
            optional_data = dict()
            optional_data["finding"] = True
            optional_data["script"] = base_name
            optional_data["message"] = message

            raise_alert_alertr(ALERTR_FIFO,
                               optional_data)

        if FROM_ADDR is not None and TO_ADDR is not None:
            mail_subject = "[Security] Finding in '%s' on host '%s'" % (base_name, socket.gethostname())
            raise_alert_mail(FROM_ADDR,
                             TO_ADDR,
                             mail_subject,
                             message)

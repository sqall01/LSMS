import json
import smtplib
import os
import time
from typing import Dict, Any


def raise_alert_alertr(alertr_fifo: str,
                       optional_data_dict: Dict[str, Any]):
    # Send message to AlertR.
    msg_dict = dict()
    msg_dict["message"] = "sensoralert"

    payload_dict = dict()
    payload_dict["state"] = 1
    payload_dict["dataType"] = 0
    payload_dict["data"] = {}
    payload_dict["hasLatestData"] = False
    payload_dict["changeState"] = False
    payload_dict["hasOptionalData"] = True
    payload_dict["optionalData"] = optional_data_dict
    msg_dict["payload"] = payload_dict

    for i in range(10):
        try:
            # Will throw an exception if FIFO file does not have a reader instead of blocking.
            fd = os.open(alertr_fifo, os.O_WRONLY | os.O_NONBLOCK)
            os.write(fd, (json.dumps(msg_dict) + "\n").encode("ascii"))
            os.close(fd)
            # Give AlertR sensor time to process the data.
            # Otherwise, a parsing error might occur on the FIFO sensor when multiple messages were mixed.
            time.sleep(2)
            break

        except Exception:
            time.sleep(5)


def raise_alert_mail(from_addr: str,
                     to_addr: str,
                     subject: str,
                     message: str):

    email_header = "From: %s\r\nTo: %s\r\nSubject: %s\r\n" \
                   % (from_addr, to_addr, subject)

    for i in range(10):
        try:
            smtp_server = smtplib.SMTP("127.0.0.1", 25)
            smtp_server.sendmail(from_addr,
                                 to_addr,
                                 email_header + message)
            smtp_server.quit()
            break

        except Exception:
            time.sleep(5)

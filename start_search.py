#!/usr/bin/env python3

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: https://h4des.org
# github: https://github.com/sqall01
#
# Licensed under the MIT License.

import os
import subprocess
import socket
import sys
import time
from scripts.config.config import START_PROCESS_TIMEOUT, TO_ADDR, FROM_ADDR, ALERTR_FIFO
from scripts.lib.alerts import raise_alert_alertr, raise_alert_mail


if __name__ == '__main__':

    print_output = False
    if ALERTR_FIFO is None and FROM_ADDR is None and TO_ADDR is None:
        print_output = True

    script_dir = os.path.dirname(os.path.abspath(__file__)) + "/scripts/"
    for script in os.listdir(script_dir):
        # Execute all python scripts.
        if script[-3:] == ".py" and script != "__init__.py":

            if print_output:
                print("Executing %s" % script)

            to_execute = [script_dir + script]

            # Pass arguments to scripts.
            if len(sys.argv) > 1:
                to_execute.extend(sys.argv[1:])

            process = None
            try:
                process = subprocess.Popen(to_execute,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)

                process.wait(START_PROCESS_TIMEOUT)

            # Catch timeout.
            except subprocess.TimeoutExpired:
                if print_output:
                    print("Script '%s' timed out." % script)

                else:
                    if ALERTR_FIFO is not None:

                        hostname = socket.gethostname()
                        optional_data = dict()
                        optional_data["script"] = script
                        optional_data["hostname"] = hostname
                        message = "Script '%s' on host '%s' timed out." % (script, hostname)
                        optional_data["message"] = message

                        raise_alert_alertr(ALERTR_FIFO,
                                           optional_data)

                    if FROM_ADDR is not None and TO_ADDR is not None:

                        hostname = socket.gethostname()
                        subject = "[Security] Script '%s' on '%s' timed out" % (script, hostname)
                        message = "Script '%s' on host '%s' timed out." % (script, hostname)

                        raise_alert_mail(FROM_ADDR,
                                         TO_ADDR,
                                         subject,
                                         message)

            # Catch any execution error.
            except Exception as e:
                if print_output:
                    print("Executing script '%s' raised error: %s" % (script, str(e)))

                else:
                    if ALERTR_FIFO is not None:

                        hostname = socket.gethostname()
                        optional_data = dict()
                        optional_data["script"] = script
                        optional_data["hostname"] = hostname
                        message = "Executing script '%s' on host '%s' raised error: %s" % (script, hostname, str(e))
                        optional_data["message"] = message

                        raise_alert_alertr(ALERTR_FIFO,
                                           optional_data)

                    if FROM_ADDR is not None and TO_ADDR is not None:

                        hostname = socket.gethostname()
                        subject = "[Security] Executing script '%s' on '%s' raised error" % (script, hostname)
                        message = "Executing script '%s' on host '%s' raised error: %s" % (script, hostname, str(e))

                        raise_alert_mail(FROM_ADDR,
                                         TO_ADDR,
                                         subject,
                                         message)

                continue

            exit_code = process.poll()

            # Process did not terminate yet.
            if exit_code is None:
                process.terminate()
                time.sleep(5)
                exit_code = process.poll()

                # Kill process if not exited.
                if exit_code != -15:
                    if print_output:
                        print("Script '%s' did not terminate. Killing it." % script)

                    else:
                        if ALERTR_FIFO is not None:

                            hostname = socket.gethostname()
                            optional_data = dict()
                            optional_data["script"] = script
                            optional_data["hostname"] = hostname
                            message = "Script '%s' on host '%s' did not terminate. Killing it." % (script, hostname)
                            optional_data["message"] = message

                            raise_alert_alertr(ALERTR_FIFO,
                                               optional_data)

                        if FROM_ADDR is not None and TO_ADDR is not None:

                            hostname = socket.gethostname()
                            subject = "[Security] Script '%s' on '%s' did not terminate" % (script, hostname)
                            message = "Script '%s' on host '%s' did not terminate. Killing it." % (script, hostname)

                            raise_alert_mail(FROM_ADDR,
                                             TO_ADDR,
                                             subject,
                                             message)

                    # noinspection PyBroadException
                    try:
                        process.kill()
                    except:
                        pass

            # Process executed successfully.
            elif exit_code == 0:
                if print_output:
                    stdout, stderr = process.communicate()
                    print(stdout.decode("ascii"))
                    print("")

                continue

            # Process encountered error.
            else:
                if print_output:
                    print("Script '%s' exited with exit code: %d" % (script, exit_code))

                else:
                    if ALERTR_FIFO is not None:
                        hostname = socket.gethostname()
                        optional_data = dict()
                        optional_data["script"] = script
                        optional_data["hostname"] = hostname
                        message = "Script '%s' on host '%s' exited with exit code '%d'." % (script, hostname, exit_code)
                        optional_data["message"] = message

                        raise_alert_alertr(ALERTR_FIFO,
                                           optional_data)

                    if FROM_ADDR is not None and TO_ADDR is not None:
                        hostname = socket.gethostname()
                        subject = "[Security] Script '%s' on '%s' unsuccessful" % (script, hostname)
                        message = "Script '%s' on host '%s' exited with exit code '%d'." % (script, hostname, exit_code)

                        raise_alert_mail(FROM_ADDR,
                                         TO_ADDR,
                                         subject,
                                         message)

                # noinspection PyBroadException
                try:
                    process.kill()
                except:
                    pass

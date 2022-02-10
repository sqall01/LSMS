import json
import os
import stat
from typing import Dict, Any


class StateException(Exception):
    pass


def load_state(state_dir: str) -> Dict[str, Any]:
    state_file = os.path.join(state_dir, "state")
    state_data = {}
    if os.path.isfile(state_file):
        data = None
        try:
            with open(state_file, 'rt') as fp:
                data = fp.read()
            if data is None:
                raise StateException("Read state data is None.")

            state_data = json.loads(data)

        except Exception as e:
            raise StateException("State data: '%s'; Exception: '%s'" % (str(data), str(e)))

    return state_data


def store_state(state_dir: str, state_data: Dict[str, Any]):
    # Create state dir if it does not exist.
    if not os.path.exists(state_dir):
        os.makedirs(state_dir)

    state_file = os.path.join(state_dir, "state")

    with open(state_file, 'wt') as fp:
        fp.write(json.dumps(state_data))

    os.chmod(state_file, stat.S_IREAD | stat.S_IWRITE)



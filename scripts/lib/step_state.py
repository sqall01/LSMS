import os
import json
import stat
from typing import Dict, Any

from .state import StateException
from .util_file import FileLocation


class StepLocation(FileLocation):
    def __init__(self, location: str, search_recursive: bool):
        super().__init__(location)
        self._search_recursive = search_recursive

    @property
    def search_recursive(self) -> bool:
        return self._search_recursive


class StepStateException(StateException):
    def __init__(self, msg: str):
        super().__init__(msg)


def load_step_state(state_dir: str) -> Dict[str, Any]:
    state_file = os.path.join(state_dir, "step_state")
    state_data = {"next_step": 0}
    if os.path.isfile(state_file):
        data = None
        try:
            with open(state_file, 'rt') as fp:
                data = fp.read()
            if data is None:
                raise StepStateException("Read state data is None.")

            state_data = json.loads(data)

        except Exception as e:
            raise StepStateException("State data: '%s'; Exception: '%s'" % (str(data), str(e)))

    return state_data


def store_step_state(state_dir: str, state_data: Dict[str, Any]):
    # Create state dir if it does not exist.
    if not os.path.exists(state_dir):
        os.makedirs(state_dir)

    state_file = os.path.join(state_dir, "step_state")

    with open(state_file, 'wt') as fp:
        fp.write(json.dumps(state_data))

    os.chmod(state_file, stat.S_IREAD | stat.S_IWRITE)

import os

from typing import List


class FileLocation:
    """
    Class that stores a location of a file or directory.
    """

    def __init__(self, location: str):
        self._location = location

    @property
    def location(self) -> str:
        return self._location


def apply_directory_whitelist(dir_whitelist: List[FileLocation], files: List[FileLocation]) -> List[FileLocation]:
    """
    Applies a whitelist containing directories to the given file list. The whitelist contains directories
    that are considered whitelisted. If the whitelist contains the directory "/home" then all files
    stored in "/home" are removed from the result (e.g., "/home/user/test.txt").

    :param dir_whitelist:
    :param files:
    :return: list of files that do not match whitelist
    """
    if not dir_whitelist:
        return files

    # Extract the components of the whitelist paths (pre-process it to reduces processing steps).
    whitelist_path_components_list = []
    for whitelist_entry in dir_whitelist:
        whitelist_path = os.path.normpath(whitelist_entry.location)
        whitelist_path_components = []
        while True:
            whitelist_path, component = os.path.split(whitelist_path)
            if not component:
                break
            whitelist_path_components.insert(0, component)
        whitelist_path_components_list.append(whitelist_path_components)

    new_files = []
    for file in files:
        is_whitelisted = False

        # Extract the components of the path to the file.
        path = os.path.dirname(os.path.normpath(file.location))
        path_components = []
        while True:
            path, component = os.path.split(path)
            if not component:
                break
            path_components.insert(0, component)

        for whitelist_path_components in whitelist_path_components_list:

            # Skip case such as "whitelist: /usr/local/bin" and "file path: /usr"
            if len(whitelist_path_components) > len(path_components):
                continue

            # NOTE: this check also works if "/" is whitelisted, since the whitelist components are empty and
            # thus the file is counted as whitelisted.
            is_whitelisted = True
            for i in range(len(whitelist_path_components)):
                if whitelist_path_components[i] != path_components[i]:
                    is_whitelisted = False
            if is_whitelisted:
                break

        if not is_whitelisted:
            new_files.append(file)
    return new_files


def apply_file_whitelist(file_whitelist: List[FileLocation], files: List[FileLocation]) -> List[FileLocation]:
    """
    Applies a whitelist containing files to the given file list. The whitelist contains files
    that are considered whitelisted. If the whitelist contains the file "/home/user/test.txt" than all occurrences of
    this file in the file list will be removed.

    :param file_whitelist:
    :param files:
    :return: list of files that do not match whitelist
    """
    if not file_whitelist:
        return files

    new_files = []
    for file in files:
        is_whitelisted = False
        for whitelist_file in file_whitelist:
            if os.path.samefile(file.location, whitelist_file.location):
                is_whitelisted = True
                break
        if not is_whitelisted:
            new_files.append(file)
    return new_files

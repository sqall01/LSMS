from typing import List

# List of directories to search for hidden ELF files. Defaults to "/".
SEARCH_LOCATIONS = []  # type: List[str]

# To prevent a timeout if this script is run regularly for monitoring,
# the search can be done in steps for each location given in SEARCH_LOCATIONS.
# Steps mean if you have location_A, the first execution of this script will
# process location_A non-recursively and terminates,
# the second execution will process location_A/subdir_A recursively and terminates,
# the third execution will process location_A/subdir_B recursively and terminates and so on.
# After all subdirectories where processed, the subsequent execution will begin again with location_A non-recursively.
SEARCH_IN_STEPS = False

# List of directories to ignore.
HIDDEN_EXE_DIRECTORY_WHITELIST = []  # type: List[str]

# List of hidden ELF files to ignore.
HIDDEN_EXE_FILE_WHITELIST = []  # type: List[str]

# Is the script allowed to run or not?
ACTIVATED = True

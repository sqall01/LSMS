from typing import List


class PasswdException(Exception):
    pass


class SystemUser:

    def __init__(self,
                 name: str,
                 password: str,
                 uid: int,
                 gid: int,
                 info: str,
                 home: str,
                 shell: str):
        self._name = name
        self._password = password
        self._uid = uid
        self._gid = gid
        self._info = info
        self._home = home
        self._shell = shell

    def __str__(self):
        return "%s:%s:%d:%d:%s:%s:%s" % (self._name,
                                         self._password,
                                         self._uid,
                                         self._gid,
                                         self._info,
                                         self._home,
                                         self._shell)

    @staticmethod
    def from_passwd_line(passwd_line: str):
        line_split = passwd_line.split(":")
        return SystemUser(line_split[0],
                          line_split[1],
                          int(line_split[2]),
                          int(line_split[3]),
                          line_split[4],
                          line_split[5],
                          line_split[6])

    @property
    def name(self) -> str:
        return self._name

    @property
    def password(self) -> str:
        return self._password

    @property
    def uid(self) -> int:
        return self._uid

    @property
    def gid(self) -> int:
        return self._gid

    @property
    def info(self) -> str:
        return self._info

    @property
    def home(self) -> str:
        return self._home

    @property
    def shell(self) -> str:
        return self._shell


def get_system_users() -> List[SystemUser]:
    """
    Gets the system's users from /etc/passwd
    :return:
    """
    user_list = []
    try:
        with open("/etc/passwd", 'rt') as fp:
            for line in fp:
                if line.strip() == "":
                    continue
                user_list.append(SystemUser.from_passwd_line(line.strip()))

    except Exception as e:
        raise PasswdException(str(e))

    return user_list

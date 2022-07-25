from __future__ import annotations
from typing import overload


class Version(tuple):
    @overload
    def __new__(self, major: int = 1, minor: int = 0, build: int = 0):
        ...

    @overload
    def __new__(self, ver_str: str = '1.0.0'):
        ...

    def __new__(self, ver=None, minor=None, build=None):
        if ver is None:
            ver = '1.0.0'
        if not minor is None:
            if build is None:
                build = 0
            v = [int(ver), int(minor), int(build)]
        elif isinstance(ver, str):
            v = [int(x) for x in ver.split('.')]
        else:
            return self.__new__(self, str(ver))
            # raise ArgumentError('invalid version')
        return super().__new__(self, v)

    def __repr__(self) -> str:
        return '.'.join([str(x) for x in self])

    def __lt__(self, __x: Version) -> bool:
        if isinstance(__x, str):
            __x = Version(__x)
        return super().__lt__(__x)

    def __gt__(self, __x: Version) -> bool:
        if isinstance(__x, str):
            __x = Version(__x)
        return super().__gt__(__x)

    def __eq__(self, __x: object) -> bool:
        if isinstance(__x, str):
            __x = Version(__x)
        return super().__eq__(__x)

    def __ne__(self, __x: object) -> bool:
        if isinstance(__x, str):
            __x = Version(__x)
        return super().__ne__(__x)

    def __ge__(self, __x: Version) -> bool:
        if isinstance(__x, str):
            __x = Version(__x)
        return super().__ge__(__x)

    def __le__(self, __x: Version) -> bool:
        if isinstance(__x, str):
            __x = Version(__x)
        return super().__le__(__x)


if __name__ == '__main__':
    assert Version(1, 0, 1) > Version(1, 0, 0)
    assert Version(1, 0, 1) > Version()
    assert Version(1, 0, 1) > Version('1.0.0')
    assert Version(1, 0, 1) == Version('1.0.1')
    assert Version(1, 0, 1) < Version('1.0.2')
    assert Version(1, 0, 1) < '1.0.2'
    assert Version(1, 0, 2) == '1.0.2'
    assert str(Version('1.0.2')) == '1.0.2'

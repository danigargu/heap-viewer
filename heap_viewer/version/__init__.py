class Version(float):
    def __init__(self, ver: str = None):
        self = ver if isinstance(ver, float) else float(ver)
        print('self version', self)

    def __lt__(self, __x: float) -> bool:
        if isinstance(__x, str):
            __x = float(__x)
        print('compare', self, __x)
        return super().__lt__(__x)

    def __gt__(self, __x: float) -> bool:
        if isinstance(__x, str):
            __x = float(__x)
        print('compare', self, __x)
        return super().__gt__(__x)

    def __eq__(self, __x: object) -> bool:
        if isinstance(__x, str):
            __x = float(__x)
        print('compare', self, __x)
        return super().__eq__(__x)

    def __ne__(self, __x: object) -> bool:
        if isinstance(__x, str):
            __x = float(__x)
        print('compare', self, __x)
        return super().__ne__(__x)

    def __ge__(self, __x: float) -> bool:
        if isinstance(__x, str):
            __x = float(__x)
        print('compare', self, __x)
        return super().__ge__(__x)

    def __le__(self, __x: float) -> bool:
        if isinstance(__x, str):
            __x = float(__x)
        print('compare', self, __x)
        return super().__le__(__x)

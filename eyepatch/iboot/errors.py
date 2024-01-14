import eyepatch


class iBootError(eyepatch.EyepatchError):
    pass


class InvalidStage(iBootError):
    pass


class UnknownPlatform(iBootError):
    pass

import eyepatch.aarch64
import eyepatch.base


class ByteString(eyepatch.base._ByteString, eyepatch.aarch64._XrefMixin):
    pass

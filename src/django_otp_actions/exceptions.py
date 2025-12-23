class OTPException(Exception):
    """Base exception for all OTP-related errors."""

    pass


class SessionExpiredException(OTPException):
    """Raised when OTP session has expired (15 min window)."""

    pass


class OTPExpiredException(OTPException):
    """Raised when OTP code has expired (5 min window)."""

    pass


class MaxRetriesExceededException(OTPException):
    """Raised when maximum retry attempts have been exceeded."""

    pass



class InvalidOTPException(OTPException):
    """
    Raised when OTP code is invalid.
    Stores the updated context (with incremented retry count) to return to the client.
    """
    def __init__(self, message, new_context=None):
        super().__init__(message)
        self.new_context = new_context

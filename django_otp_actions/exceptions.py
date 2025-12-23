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
    Contains updated context with incremented retry count.
    """

    

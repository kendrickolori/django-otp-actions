from functools import wraps
from rest_framework.response import Response
from rest_framework import status

# We assume these exceptions are mapped to status codes in your settings or handler
from .services import generate_otp, verify_otp, increment_retry_count
from .exceptions import (
    InvalidOTPException,
    OTPExpiredException,
    SessionExpiredException,
    MaxRetriesExceededException,
    OTPException,
)


def otp_protected():
    """Injects generate_otp into the request object."""

    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            request.generate_otp = generate_otp
            return func(request, *args, **kwargs)

        return wrapper

    return decorator


def require_otp_verification():
    """Validates OTP. Returns Response on failure, executes view on success."""

    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            otp = str(request.data.get("otp") or "").strip()
            encrypted_context = str(request.data.get("context") or "").strip()

            if not otp or not encrypted_context:
                return Response(
                    {
                        "error": "OTP and context are required",
                        "error_code": "MISSING_FIELDS",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                # Success path
                context = verify_otp(otp, encrypted_context)
                request.otp_verified = True
                request.otp_context = context
                return func(request, *args, **kwargs)

            except InvalidOTPException as e:
                # We return the response here to include the NEW encrypted_context
                return Response(
                    {
                        "error": str(e),
                        "error_code": "INVALID_OTP",
                        "context": increment_retry_count(encrypted_context),
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            except (OTPExpiredException, SessionExpiredException) as e:
                code = (
                    "OTP_EXPIRED"
                    if isinstance(e, OTPExpiredException)
                    else "SESSION_EXPIRED"
                )
                return Response(
                    {"error": str(e), "error_code": code}, status=status.HTTP_410_GONE
                )
            except MaxRetriesExceededException as e:
                return Response(
                    {"error": str(e), "error_code": "MAX_RETRIES_EXCEEDED"},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )
            except Exception:
                return Response(
                    {"error": "Internal Error", "error_code": "OTP_ERROR"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        return wrapper

    return decorator

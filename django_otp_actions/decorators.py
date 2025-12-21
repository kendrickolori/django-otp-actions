from functools import wraps
from .services import generate_otp, validate_otp
from .exceptions import (
    InvalidOTPException,
    OTPExpiredException,
    SessionExpiredException,
    MaxRetriesExceededException,
    OTPException,
)
from rest_framework.response import Response
from rest_framework import status


def otp_protected():
    """Decorator that injects generate_otp into request."""

    def decorator(func):
        @wraps(func)  # ✅ Apply as decorator to wrapper
        def wrapper(request, *args, **kwargs):
            request.generate_otp = generate_otp
            return func(request, *args, **kwargs)

        return wrapper

    return decorator


def verify_otp():
    """Decorator that validates OTP before executing view."""

    def decorator(func):
        @wraps(func)  # ✅ Apply as decorator to wrapper
        def wrapper(request, *args, **kwargs):
            otp = str(request.data.get("otp", ""))
            encrypted_context = request.data.get("context", "")

            if not otp or not encrypted_context:
                return Response(
                    {"error": "OTP and context are required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                context = validate_otp(otp, encrypted_context)
                request.otp_verified = True
                request.otp_context = context
                return func(request, *args, **kwargs)

            except InvalidOTPException as e:
                return Response(
                    {"error": str(e), "context": e.updated_context},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            except OTPExpiredException as e:
                return Response(
                    {"error": str(e), "error_code": "OTP_EXPIRED"},
                    status=status.HTTP_410_GONE,
                )

            except SessionExpiredException as e:
                return Response(
                    {"error": str(e), "error_code": "SESSION_EXPIRED"},
                    status=status.HTTP_410_GONE,
                )

            except MaxRetriesExceededException as e:
                return Response(
                    {"error": str(e), "error_code": "MAX_RETRIES_EXCEEDED"},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            except OTPException as e:
                return Response(
                    {"error": str(e), "error_code": "OTP_ERROR"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            except Exception as e:
                return Response(
                    {
                        "error": "An unexpected error occurred",
                        "error_code": "INTERNAL_ERROR",
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        return wrapper

    return decorator

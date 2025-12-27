# mixins.py or otp_utils.py

from functools import wraps
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse
from .services import generate_otp, verify_otp
from .exceptions import (
    InvalidOTPException,
    OTPExpiredException,
    SessionExpiredException,
    MaxRetriesExceededException,
)


class OTPProtectedMixin:
    """
    Adds `request.generate_otp` function to all DRF views.
    Use this whenever you need to send/generate an OTP.
    """
    def dispatch(self, request, *args, **kwargs):
        request.generate_otp = generate_otp
        return super().dispatch(request, *args, **kwargs)


class OTPVerifiedMixin:
    """
    Verifies OTP before allowing access.
    Use with DRF views only (APIView, ViewSet, etc.).
    """
    def dispatch(self, request, *args, **kwargs):
        # Only apply verification on methods that might submit OTP (usually POST)
        if request.method in ["POST", "PUT", "PATCH"]:
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
                context = verify_otp(otp, encrypted_context)
                request.otp_verified = True
                request.otp_context = context
            except InvalidOTPException as e:
                return Response(
                    {
                        "error": str(e),
                        "error_code": "INVALID_OTP",
                        "context": getattr(e, "new_context", None),
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            except (OTPExpiredException, SessionExpiredException) as e:
                code = "OTP_EXPIRED" if isinstance(e, OTPExpiredException) else "SESSION_EXPIRED"
                return Response(
                    {"error": str(e), "error_code": code},
                    status=status.HTTP_410_GONE,
                )
            except MaxRetriesExceededException:
                return Response(
                    {"error": "Too many attempts", "error_code": "MAX_RETRIES_EXCEEDED"},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )
            except Exception:
                return Response(
                    {"error": "OTP verification failed", "error_code": "OTP_ERROR"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        return super().dispatch(request, *args, **kwargs)


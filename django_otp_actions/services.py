import time
import random
from datetime import datetime, timedelta
from django.conf import settings
import json
from cryptography.fernet import Fernet


# Custom Exceptions
class OTPException(Exception):
    """Base exception for OTP-related errors"""

    pass


class OTPExpiredException(OTPException):
    """Raised when OTP has expired"""

    pass


class InvalidOTPException(OTPException):
    """Raised when OTP doesn't match"""

    pass


class SessionExpiredException(OTPException):
    """Raised when session has expired"""

    pass


class MaxRetriesExceededException(OTPException):
    """Raised when maximum retry attempts exceeded"""

    pass


def encrypt_context(context):
    key = settings.OTP_SIGNING_KEY
    if isinstance(key, str):
        key = key.encode("utf-8")

    f = Fernet(key)
    context_json = json.dumps(context)
    context_bytes = context_json.encode("utf-8")
    encrypted = f.encrypt(context_bytes)

    return encrypted.decode("utf-8")


def decrypt_context(encrypted_context):
    key = settings.OTP_SIGNING_KEY
    if isinstance(key, str):
        key = key.encode("utf-8")

    f = Fernet(key)
    decrypted_bytes = f.decrypt(encrypted_context.encode("utf-8"))
    decrypted_json = decrypted_bytes.decode("utf-8")
    context_dict = json.loads(decrypted_json)

    return context_dict


def generate_otp(identifier=None, metadata=None, max_retries=3):
    """
    Generate OTP and encrypted context.

    Args:
        identifier: Unique identifier (email, phone, etc.)
        metadata: Additional metadata to store
        max_retries: Maximum number of retry attempts allowed

    Returns:
        tuple: (otp, encrypted_context)
    """
    otp = random.randint(100000, 999999)

    now = datetime.now()

    context = {
        "identifier": identifier,
        "code": str(otp),
        "metadata": metadata,
        "timestamp": now.timestamp(),
        "otp_expiry": (now + timedelta(minutes=5)).timestamp(),
        "session_expiry": (now + timedelta(minutes=15)).timestamp(),
        "retry_count": 0,
        "max_retries": max_retries,
    }

    encrypted_context = encrypt_context(context)
    return (str(otp), encrypted_context)


def otp_valid(otp, encrypted_context):
    """
    Validate OTP against encrypted context.

    Args:
        otp: The OTP code to validate
        encrypted_context: The encrypted context string

    Returns:
        tuple: (is_valid, updated_encrypted_context)

    Raises:
        SessionExpiredException: If session has expired
        OTPExpiredException: If OTP has expired
        MaxRetriesExceededException: If max retry attempts exceeded
        InvalidOTPException: If OTP doesn't match
    """
    try:
        context = decrypt_context(encrypted_context)
        current_time = datetime.now().timestamp()

        # Check session expiry first
        if current_time > context.get("session_expiry", 0):
            raise SessionExpiredException(
                "Session has expired. Please request a new OTP."
            )

        # Check OTP expiry
        if current_time > context.get("otp_expiry", 0):
            raise OTPExpiredException("OTP has expired. Please request a new OTP.")

        # Increment retry count
        context["retry_count"] = context.get("retry_count", 0) + 1

        # Check if max retries exceeded (check after incrementing)
        if context["retry_count"] > context.get("max_retries", 3):
            raise MaxRetriesExceededException(
                f"Maximum retry attempts ({context.get('max_retries', 3)}) exceeded. Please request a new OTP."
            )

        # Update encrypted context with new retry count
        updated_encrypted_context = encrypt_context(context)

        # Check if OTP matches
        if context.get("code") != str(otp):
            raise InvalidOTPException(
                f"Invalid OTP. Attempts remaining: {context.get('max_retries', 3) - context['retry_count']}"
            )

        # OTP is valid
        return (True, updated_encrypted_context)

    except OTPException:
        # Re-raise OTP-related exceptions
        raise
    except Exception as e:
        # Handle decryption or other errors
        raise OTPException(f"Error validating OTP: {str(e)}")


def invalidate_otp(encrypted_context):
    """
    Invalidate an OTP by setting its expiry to the past.

    Args:
        encrypted_context: The encrypted context string

    Returns:
        str: Updated encrypted context with expired OTP
    """
    try:
        context = decrypt_context(encrypted_context)
        context["otp_expiry"] = 0  # Set to past timestamp
        return encrypt_context(context)
    except Exception as e:
        raise OTPException(f"Error invalidating OTP: {str(e)}")

import time
import secrets
import random
from datetime import datetime, timedelta
from django.conf import settings
import json
from cryptography.fernet import Fernet
from .exceptions import (
    OTPException,
    OTPExpiredException,
    MaxRetriesExceededException,
    SessionExpiredException,
    InvalidOTPException,
)


def encrypt_context(context):
    """Encrypt context dictionary to string."""
    key = settings.OTP_SIGNING_KEY
    if isinstance(key, str):
        key = key.encode("utf-8")

    f = Fernet(key)
    context_json = json.dumps(context)
    context_bytes = context_json.encode("utf-8")
    encrypted = f.encrypt(context_bytes)

    return encrypted.decode("utf-8")


def decrypt_context(encrypted_context):
    """Decrypt context string to dictionary."""
    key = settings.OTP_SIGNING_KEY
    if isinstance(key, str):
        key = key.encode("utf-8")

    f = Fernet(key)
    decrypted_bytes = f.decrypt(encrypted_context.encode("utf-8"))
    decrypted_json = decrypted_bytes.decode("utf-8")
    context_dict = json.loads(decrypted_json)

    return context_dict


def generate_otp(identifier=None ,metadata=None, max_retries=3,length=6):
    """
    Generate OTP and encrypted context.

    Note: Each call creates a NEW session window (15 minutes).
    Requesting a new code resets the session timer.

    Args:
        identifier: Unique identifier (email, phone, etc.)
        metadata: Additional metadata to store
        max_retries: Maximum number of retry attempts allowed (default: 3)

    Returns:
        tuple: (otp, encrypted_context)
    """
    otp = ''.join(str(secrets.randbelow(10)) for _ in range(length))
    print(otp)
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


def validate_otp(otp, encrypted_context):
    """
    Validate OTP against encrypted context.

    Args:
        otp: The OTP code to validate
        encrypted_context: The encrypted context string

    Returns:
        dict: The decrypted context if valid

    Raises:
        SessionExpiredException: If session has expired
        OTPExpiredException: If OTP has expired
        MaxRetriesExceededException: If max retry attempts exceeded
        InvalidOTPException: If OTP doesn't match (includes updated context)
        OTPException: For any other errors
    """
    try:
        context = decrypt_context(encrypted_context)
        current_time = datetime.now().timestamp()

        # Check session expiry first (most critical)
        if current_time > context.get("session_expiry", 0):
            raise SessionExpiredException(
                "Session has expired. Please request a new OTP."
            )

        # Check OTP expiry
        if current_time > context.get("otp_expiry", 0):
            raise OTPExpiredException("OTP has expired. Please request a new OTP code.")

        # Check retry count BEFORE incrementing
        if context["retry_count"] >= context.get("max_retries", 3):
            raise MaxRetriesExceededException(
                f"Maximum retry attempts ({context.get('max_retries', 3)}) exceeded. "
                "Please request a new OTP code."
            )

        # Check if OTP matches
        if context.get("code") != str(otp):
            # Increment retry count
            context["retry_count"] += 1
            updated_context = encrypt_context(context)

            attempts_remaining = context.get("max_retries", 3) - context["retry_count"]

            raise InvalidOTPException(
                message=f"Invalid OTP. Attempts remaining: {attempts_remaining}",
                updated_context=updated_context,
            )

        # OTP is valid - return the context
        return context

    except (
        OTPExpiredException,
        MaxRetriesExceededException,
        SessionExpiredException,
        InvalidOTPException,
    ):
        # Re-raise OTP-specific exceptions as-is
        raise
    except Exception as e:
        # Wrap any other errors (decryption, JSON parsing, etc.)
        raise OTPException(f"Error validating OTP: {str(e)}")


def verify_otp(otp, encrypted_context):
    """
    Verify OTP and return context if valid.

    This is a convenience wrapper around validate_otp that returns
    the context on success. All exceptions are propagated upward.

    Args:
        otp: The OTP code to verify
        encrypted_context: The encrypted context string

    Returns:
        dict: The decrypted context with metadata if valid

    Raises:
        All exceptions from validate_otp are propagated upward
    """
    # Let all exceptions bubble up - decorator will handle them
    context = validate_otp(otp, encrypted_context)
    return context

import hashlib
import secrets
from datetime import datetime, timedelta
from django.conf import settings
import json
from cryptography.fernet import Fernet, InvalidToken
from .exceptions import (
    OTPException,
    OTPExpiredException,
    MaxRetriesExceededException,
    SessionExpiredException,
    InvalidOTPException,
)


def encrypt_context(context):
    """
    Encrypt context dictionary to string using Fernet symmetric encryption.
    """
    try:
        key = settings.OTP_SIGNING_KEY
        if isinstance(key, str):
            key = key.encode("utf-8")

        f = Fernet(key)
        context_json = json.dumps(context)
        context_bytes = context_json.encode("utf-8")
        encrypted = f.encrypt(context_bytes)

        return encrypted.decode("utf-8")
    except (ValueError, TypeError, AttributeError) as e:
        raise OTPException(f"Encryption failed: {str(e)}")


def decrypt_context(encrypted_context):
    """
    Decrypt encrypted context string back to dictionary.
    """
    try:
        key = settings.OTP_SIGNING_KEY
        if isinstance(key, str):
            key = key.encode("utf-8")

        f = Fernet(key)
        decrypted_bytes = f.decrypt(encrypted_context.encode("utf-8"))
        decrypted_json = decrypted_bytes.decode("utf-8")
        context_dict = json.loads(decrypted_json)

        return context_dict
    except InvalidToken:
        raise OTPException(
            "Failed to decrypt context. This may be due to key rotation, "
            "corrupted data, or an invalid token. Please request a new OTP."
        )
    except (ValueError, TypeError, json.JSONDecodeError) as e:
        raise OTPException(f"Decryption failed: {str(e)}")


def generate_otp(identifier=None, metadata=None, max_retries=3, length=6):
    """
    Generate a cryptographically secure OTP and encrypted context.
    """
    try:
        # Generate cryptographically secure OTP
        otp = "".join(str(secrets.randbelow(10)) for _ in range(length))

        now = datetime.now()

        # Hash OTP before storing
        otp_hash = hashlib.sha256(otp.encode("utf-8")).hexdigest()

        context = {
            "identifier": identifier,
            "otp_hash": otp_hash,
            "metadata": metadata,
            "timestamp": now.timestamp(),
            "otp_expiry": (now + timedelta(minutes=5)).timestamp(),
            "session_expiry": (now + timedelta(minutes=15)).timestamp(),
            "retry_count": 0,
            "max_retries": max_retries,
        }

        encrypted_context = encrypt_context(context)
        return (otp, encrypted_context)

    except OTPException:
        raise
    except Exception as e:
        raise OTPException(f"Failed to generate OTP: {str(e)}")


def increment_retry_count(encrypted_context):
    """
    Utility to manually increment retry count. 
    (Kept for backward compatibility/testing, though validation now handles this internally).
    """
    try:
        context = decrypt_context(encrypted_context)
        context["retry_count"] += 1
        return encrypt_context(context)
    except OTPException:
        raise
    except Exception as e:
        raise OTPException(f"Failed to increment retry count: {str(e)}")


def validate_otp(otp, encrypted_context):
    """
    Validate OTP against encrypted context.
    
    If OTP is invalid, this function now:
    1. Increments the retry count in the dictionary.
    2. Re-encrypts the context.
    3. Raises InvalidOTPException containing the NEW encrypted context.
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
            raise OTPExpiredException("OTP has expired. Please request a new OTP code.")

        # Check retry count
        max_retries = context.get("max_retries", 3)
        if context["retry_count"] >= max_retries:
            raise MaxRetriesExceededException(
                f"Maximum retry attempts ({max_retries}) exceeded. "
                "Please request a new OTP code."
            )

        # Validate OTP hash
        otp_str = str(otp).strip()
        otp_hash = hashlib.sha256(otp_str.encode("utf-8")).hexdigest()
        stored_hash = context.get("otp_hash", "")

        if not secrets.compare_digest(stored_hash, otp_hash):
            # --- LOGIC CHANGE: Increment and Re-encrypt ---
            context["retry_count"] += 1
            
            # Calculate remaining using the NEW state
            attempts_remaining = max_retries - context["retry_count"]
            
            # Re-encrypt the updated context
            new_encrypted_context = encrypt_context(context)
            
            raise InvalidOTPException(
                f"Invalid OTP. Attempts remaining: {attempts_remaining}",
                new_context=new_encrypted_context
            )

        # OTP is valid
        return True

    except (
        OTPExpiredException,
        MaxRetriesExceededException,
        SessionExpiredException,
        InvalidOTPException,
    ):
        raise
    except OTPException:
        raise
    except Exception as e:
        raise OTPException(f"Error validating OTP: {str(e)}")


def verify_otp(otp, encrypted_context):
    """
    Verify OTP and return decrypted context if valid.
    Wrapper around validate_otp that returns the context dict on success.
    """
    # Validate OTP (raises exceptions on failure, including InvalidOTPException with new context)
    validate_otp(otp, encrypted_context)

    # If validation succeeds, decrypt and return context
    try:
        context = decrypt_context(encrypted_context)
        return context
    except OTPException:
        raise
    except Exception as e:
        raise OTPException(f"Error retrieving context: {str(e)}")


__all__ = [
    "generate_otp",
    "validate_otp",
    "verify_otp",
    "increment_retry_count",
    "encrypt_context",
    "decrypt_context",
]

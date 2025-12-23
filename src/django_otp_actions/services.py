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

    Args:
        context (dict): Dictionary containing OTP context data

    Returns:
        str: Base64-encoded encrypted context string

    Raises:
        OTPException: If encryption fails due to invalid key or other errors

    Examples:
        >>> context = {'identifier': 'user@example.com', 'otp_hash': 'abc123'}
        >>> encrypted = encrypt_context(context)
        >>> isinstance(encrypted, str)
        True
        >>> len(encrypted) > 0
        True
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

    Args:
        encrypted_context (str): Base64-encoded encrypted context string

    Returns:
        dict: Decrypted context dictionary

    Raises:
        OTPException: If decryption fails due to invalid key, corrupted data,
                      key rotation, or invalid token

    Examples:
        >>> # Assuming you have a valid encrypted context
        >>> context = {'identifier': 'test@example.com'}
        >>> encrypted = encrypt_context(context)
        >>> decrypted = decrypt_context(encrypted)
        >>> decrypted['identifier']
        'test@example.com'
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

    Each call creates a NEW session window (15 minutes) and OTP window (5 minutes).
    Requesting a new code resets both timers.

    Args:
        identifier (str, optional): Unique identifier (email, phone, user ID, etc.)
        metadata (dict, optional): Additional metadata to store in context
        max_retries (int): Maximum verification attempts allowed (default: 3)
        length (int): Length of OTP code (default: 6)

    Returns:
        tuple: (otp_code, encrypted_context)
            - otp_code (str): The generated OTP as a string
            - encrypted_context (str): Encrypted context containing validation data

    Raises:
        OTPException: If OTP generation or encryption fails

    Examples:
        >>> otp, context = generate_otp(identifier='user@example.com', length=6)
        >>> len(otp)
        6
        >>> otp.isdigit()
        True
        >>> isinstance(context, str)
        True

        >>> # With metadata
        >>> otp, context = generate_otp(
        ...     identifier='user@example.com',
        ...     metadata={'action': 'login', 'ip': '192.168.1.1'},
        ...     max_retries=5,
        ...     length=8
        ... )
        >>> len(otp)
        8

    Security:
        - Uses secrets.randbelow() for cryptographically secure random generation
        - OTP is hashed with SHA-256 before storage
        - Context is encrypted with Fernet (AES-128-CBC)
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
        # Re-raise OTPException from encrypt_context
        raise
    except Exception as e:
        raise OTPException(f"Failed to generate OTP: {str(e)}")


def increment_retry_count(encrypted_context):
    """
    Increment the retry count in the encrypted context.

    This is a pure function that returns a new encrypted context with
    the retry count incremented by 1. It does not modify the original context.

    Args:
        encrypted_context (str): The encrypted context string

    Returns:
        str: New encrypted context with incremented retry count

    Raises:
        OTPException: If decryption or encryption fails

    Examples:
        >>> otp, context = generate_otp(identifier='user@example.com')
        >>> updated_context = increment_retry_count(context)
        >>> original = decrypt_context(context)
        >>> updated = decrypt_context(updated_context)
        >>> updated['retry_count'] == original['retry_count'] + 1
        True
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
    Validate OTP against encrypted context without side effects.

    This is a pure validation function that checks if the provided OTP is valid
    according to the encrypted context. It does NOT modify any state or increment
    retry counts - those side effects should be handled by the caller (typically
    a decorator or view layer).

    Args:
        otp (str): The OTP code to validate
        encrypted_context (str): The encrypted context string from generate_otp()

    Returns:
        bool: True if OTP is valid and all checks pass

    Raises:
        SessionExpiredException: If the 15-minute session window has expired
        OTPExpiredException: If the 5-minute OTP code has expired
        MaxRetriesExceededException: If maximum retry attempts have been exceeded
        InvalidOTPException: If the OTP code doesn't match
        OTPException: For decryption errors, invalid data, or other failures

    Examples:
        >>> otp, context = generate_otp(identifier='user@example.com')
        >>> validate_otp(otp, context)
        True

        >>> # Invalid OTP raises exception
        >>> try:
        ...     validate_otp('000000', context)
        ... except InvalidOTPException as e:
        ...     print('Invalid OTP')
        Invalid OTP

    Security:
        - Uses secrets.compare_digest() for timing-attack-resistant comparison
        - Compares SHA-256 hashes, not plaintext OTPs
        - Enforces time windows and retry limits

    Note:
        This function is pure and has no side effects. The retry count is NOT
        incremented here - callers must call increment_retry_count() separately
        when handling InvalidOTPException.
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

        # Check retry count
        if context["retry_count"] >= context.get("max_retries", 3):
            raise MaxRetriesExceededException(
                f"Maximum retry attempts ({context.get('max_retries', 3)}) exceeded. "
                "Please request a new OTP code."
            )
        otp_str = str(otp).zfill(6)
        otp_hash = hashlib.sha256(otp_str.encode("utf-8")).hexdigest()
            

        # Validate OTP using constant-time comparison
        otp_hash = hashlib.sha256(str(otp).encode("utf-8")).hexdigest()
        stored_hash = context.get("otp_hash", "")

        if not secrets.compare_digest(stored_hash, otp_hash):
            attempts_remaining = context.get("max_retries", 3) - context["retry_count"]
            raise InvalidOTPException(
                f"Invalid OTP. Attempts remaining: {attempts_remaining}"
            )

        # OTP is valid
        return True

    except (
        OTPExpiredException,
        MaxRetriesExceededException,
        SessionExpiredException,
        InvalidOTPException,
    ):
        # Re-raise OTP-specific exceptions as-is
        raise
    except OTPException:
        # Re-raise OTPException (from decrypt_context)
        raise
    except Exception as e:
        # Wrap any other unexpected errors
        raise OTPException(f"Error validating OTP: {str(e)}")


def verify_otp(otp, encrypted_context):
    """
    Verify OTP and return decrypted context if valid.

    This is a convenience wrapper around validate_otp() that returns the full
    decrypted context upon successful validation. All exceptions from validate_otp()
    are propagated upward for handling by decorators or view layers.

    Args:
        otp (str): The OTP code to verify
        encrypted_context (str): The encrypted context string

    Returns:
        dict: The decrypted context dictionary containing:
            - identifier: The user identifier
            - metadata: Any additional metadata stored
            - timestamp: When the OTP was generated
            - otp_expiry: OTP expiration timestamp
            - session_expiry: Session expiration timestamp
            - retry_count: Current retry count
            - max_retries: Maximum retries allowed

    Raises:
        SessionExpiredException: If session has expired
        OTPExpiredException: If OTP has expired
        MaxRetriesExceededException: If max retry attempts exceeded
        InvalidOTPException: If OTP doesn't match
        OTPException: For decryption or other errors

    Examples:
        >>> otp, context = generate_otp(
        ...     identifier='user@example.com',
        ...     metadata={'action': 'login'}
        ... )
        >>> result = verify_otp(otp, context)
        >>> result['identifier']
        'user@example.com'
        >>> result['metadata']['action']
        'login'

    Note:
        Unlike validate_otp() which returns a boolean, this function returns
        the full context dictionary for use in your application logic.
    """
    # Validate OTP (raises exceptions on failure)
    validate_otp(otp, encrypted_context)

    # If validation succeeds, decrypt and return context
    try:
        context = decrypt_context(encrypted_context)
        return context
    except OTPException:
        raise
    except Exception as e:
        raise OTPException(f"Error retrieving context: {str(e)}")


# Export public API
__all__ = [
    "generate_otp",
    "validate_otp",
    "verify_otp",
    "increment_retry_count",
    "encrypt_context",
    "decrypt_context",
]

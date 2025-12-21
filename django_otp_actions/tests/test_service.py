import pytest
from django.conf import settings
from cryptography.fernet import Fernet
from freezegun import freeze_time
from datetime import datetime, timedelta

# Configure Django settings before importing
# settings.configure(
# OTP_SIGNING_KEY=Fernet.generate_key()
# )

from django_otp_actions.services import (
    validate_otp,
    encrypt_context,
    decrypt_context,
    generate_otp,
)
from django_otp_actions.exceptions import (
    InvalidOTPException,
    OTPExpiredException,
    SessionExpiredException,
    MaxRetriesExceededException,
    OTPException,
)


# Test data
IDENTIFIER = "test@example.com"
METADATA = {"email": "user@example.com", "phone": "+1234567890", "name": "Test User"}


class TestEncryption:
    """Test encryption and decryption functions."""

    def test_encryption_returns_string(self):
        context = {"identifier": "test", "metadata": {"key": "value"}}
        encrypted = encrypt_context(context)

        assert encrypted is not None
        assert isinstance(encrypted, str)
        assert len(encrypted) > 0

    def test_decryption_restores_original(self):
        context = {"identifier": "test123", "metadata": {"email": "test@test.com"}}
        encrypted = encrypt_context(context)
        decrypted = decrypt_context(encrypted)

        assert context == decrypted

    def test_encryption_is_deterministic(self):
        """Same input should produce different output (due to timestamp/nonce)."""
        context = {"identifier": "test"}
        encrypted1 = encrypt_context(context)
        encrypted2 = encrypt_context(context)

        # Fernet adds random IV, so should be different
        assert encrypted1 != encrypted2


class TestOTPGeneration:
    """Test OTP generation."""

    def test_otp_is_six_digits(self):
        otp, _ = generate_otp(IDENTIFIER, METADATA)

        assert len(otp) == 6
        assert otp.isdigit()
        assert 100000 <= int(otp) <= 999999

    def test_otp_returns_encrypted_context(self):
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)

        assert encrypted_context is not None
        assert isinstance(encrypted_context, str)

    def test_generated_context_contains_correct_data(self):
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)
        decrypted = decrypt_context(encrypted_context)

        assert decrypted["identifier"] == IDENTIFIER
        assert decrypted["metadata"] == METADATA
        assert decrypted["code"] == otp
        assert decrypted["retry_count"] == 0
        assert decrypted["max_retries"] == 3

    def test_custom_max_retries(self):
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA, max_retries=5)
        decrypted = decrypt_context(encrypted_context)

        assert decrypted["max_retries"] == 5

    @freeze_time("2024-12-20 10:00:00")
    def test_otp_expiry_is_5_minutes(self):
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)
        decrypted = decrypt_context(encrypted_context)

        expected_otp_expiry = (datetime.now() + timedelta(minutes=5)).timestamp()
        assert abs(decrypted["otp_expiry"] - expected_otp_expiry) < 1  # Within 1 second

    @freeze_time("2024-12-20 10:00:00")
    def test_session_expiry_is_15_minutes(self):
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)
        decrypted = decrypt_context(encrypted_context)

        expected_session_expiry = (datetime.now() + timedelta(minutes=15)).timestamp()
        assert abs(decrypted["session_expiry"] - expected_session_expiry) < 1


class TestOTPValidation:
    """Test OTP validation logic."""

    @freeze_time("2024-12-20 10:00:00")
    def test_valid_otp_passes(self):
        """Valid OTP should return context."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)

        # Valid OTP should not raise exception
        context = validate_otp(otp, encrypted_context)

        assert context is not None
        assert context["identifier"] == IDENTIFIER
        assert context["code"] == otp

    @freeze_time("2024-12-20 10:00:00")
    def test_invalid_otp_raises_exception(self):
        """Wrong OTP code should raise InvalidOTPException."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)
        wrong_otp = "999999" if otp != "999999" else "111111"

        with pytest.raises(InvalidOTPException) as exc_info:
            validate_otp(wrong_otp, encrypted_context)

        assert "Invalid OTP" in str(exc_info.value)
        assert "Attempts remaining: 2" in str(exc_info.value)

    @freeze_time("2024-12-20 10:00:00")
    def test_invalid_otp_increments_retry_count(self):
        """Failed attempt should increment retry count in updated context."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)
        wrong_otp = "999999" if otp != "999999" else "111111"

        try:
            validate_otp(wrong_otp, encrypted_context)
        except InvalidOTPException as e:
            updated_context = e.updated_context
            decrypted = decrypt_context(updated_context)

            assert decrypted["retry_count"] == 1

    @freeze_time("2024-12-20 10:00:00")
    def test_otp_expired_raises_exception(self):
        """OTP code expired after 5 minutes should raise OTPExpiredException."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)

        # Move time forward 6 minutes (past OTP expiry)
        with freeze_time("2024-12-20 10:06:00"):
            with pytest.raises(OTPExpiredException) as exc_info:
                validate_otp(otp, encrypted_context)

            assert "OTP has expired" in str(exc_info.value)

    @freeze_time("2024-12-20 10:00:00")
    def test_session_expired_raises_exception(self):
        """Session expired after 15 minutes should raise SessionExpiredException."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)

        # Move time forward 16 minutes (past session expiry)
        with freeze_time("2024-12-20 10:16:00"):
            with pytest.raises(SessionExpiredException) as exc_info:
                validate_otp(otp, encrypted_context)

            assert "Session has expired" in str(exc_info.value)

    @freeze_time("2024-12-20 10:00:00")
    def test_max_retries_exceeded_raises_exception(self):
        """Exceeding max retries should raise MaxRetriesExceededException."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA, max_retries=3)
        wrong_otp = "999999" if otp != "999999" else "111111"

        # Attempt 1
        try:
            validate_otp(wrong_otp, encrypted_context)
        except InvalidOTPException as e:
            encrypted_context = e.updated_context

        # Attempt 2
        try:
            validate_otp(wrong_otp, encrypted_context)
        except InvalidOTPException as e:
            encrypted_context = e.updated_context

        # Attempt 3
        try:
            validate_otp(wrong_otp, encrypted_context)
        except InvalidOTPException as e:
            encrypted_context = e.updated_context

        # Attempt 4 should fail with max retries exceeded
        with pytest.raises(MaxRetriesExceededException) as exc_info:
            validate_otp(wrong_otp, encrypted_context)

        assert "Maximum retry attempts" in str(exc_info.value)

    @freeze_time("2024-12-20 10:00:00")
    def test_session_expiry_checked_before_otp_expiry(self):
        """Session expiry should be checked before OTP expiry."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)

        # Move time to 16 minutes (both expired, but session should be checked first)
        with freeze_time("2024-12-20 10:16:00"):
            with pytest.raises(SessionExpiredException):
                validate_otp(otp, encrypted_context)

    @freeze_time("2024-12-20 10:00:00")
    def test_retry_count_checked_before_otp_match(self):
        """Max retries should be checked before validating OTP."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA, max_retries=0)

        # Even with correct OTP, should fail if retries exceeded
        with pytest.raises(MaxRetriesExceededException):
            validate_otp(otp, encrypted_context)

    def test_invalid_encrypted_context_raises_otp_exception(self):
        """Invalid/corrupted encrypted context should raise OTPException."""
        with pytest.raises(OTPException) as exc_info:
            validate_otp("123456", "invalid_encrypted_string")

        assert "Error validating OTP" in str(exc_info.value)

    @freeze_time("2024-12-20 10:00:00")
    def test_otp_is_string_compared(self):
        """OTP should be compared as strings, not integers."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)

        # Pass OTP as integer - should still work due to str() conversion
        context = validate_otp(int(otp), encrypted_context)
        assert context is not None

    @freeze_time("2024-12-20 10:00:00")
    def test_valid_otp_within_5_minutes(self):
        """OTP should be valid at 4 minutes 59 seconds."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)

        # Move time forward 4 minutes 59 seconds (just before expiry)
        with freeze_time("2024-12-20 10:04:59"):
            context = validate_otp(otp, encrypted_context)
            assert context is not None


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_none_identifier(self):
        """Should handle None identifier."""
        otp, encrypted_context = generate_otp(identifier=None, metadata=METADATA)
        decrypted = decrypt_context(encrypted_context)

        assert decrypted["identifier"] is None

    def test_none_metadata(self):
        """Should handle None metadata."""
        otp, encrypted_context = generate_otp(identifier=IDENTIFIER, metadata=None)
        decrypted = decrypt_context(encrypted_context)

        assert decrypted["metadata"] is None

    def test_empty_string_identifier(self):
        """Should handle empty string identifier."""
        otp, encrypted_context = generate_otp(identifier="", metadata=METADATA)
        context = validate_otp(otp, encrypted_context)

        assert context["identifier"] == ""

    @freeze_time("2024-12-20 10:00:00")
    def test_otp_with_leading_zeros(self):
        """OTP code like '000123' should be handled correctly."""
        # This tests string comparison, not integer comparison
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)

        # Manually create context with leading zero OTP
        context = decrypt_context(encrypted_context)
        context["code"] = "000123"
        encrypted_context = encrypt_context(context)

        result = validate_otp("000123", encrypted_context)
        assert result is not None


class TestVerifyOTP:
    """Test the verify_otp convenience wrapper."""

    @freeze_time("2024-12-20 10:00:00")
    def test_verify_otp_returns_context_on_success(self):
        """verify_otp should return context when OTP is valid."""
        from django_otp_actions.services import verify_otp

        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)

        context = verify_otp(otp, encrypted_context)

        assert context is not None
        assert context["identifier"] == IDENTIFIER
        assert context["metadata"] == METADATA
        assert context["code"] == otp

    @freeze_time("2024-12-20 10:00:00")
    def test_verify_otp_propagates_invalid_exception(self):
        """verify_otp should propagate InvalidOTPException."""
        from django_otp_actions.services import verify_otp

        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)
        wrong_otp = "999999" if otp != "999999" else "111111"

        with pytest.raises(InvalidOTPException):
            verify_otp(wrong_otp, encrypted_context)

    @freeze_time("2024-12-20 10:00:00")
    def test_verify_otp_propagates_expired_exception(self):
        """verify_otp should propagate OTPExpiredException."""
        from django_otp_actions.services import verify_otp

        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)

        # Move time forward past OTP expiry
        with freeze_time("2024-12-20 10:06:00"):
            with pytest.raises(OTPExpiredException):
                verify_otp(otp, encrypted_context)


class TestEncryptionWithBytesKey:
    """Test encryption when key is already bytes (not string)."""

    def test_encrypt_context_with_bytes_key(self):
        """Test encryption when OTP_SIGNING_KEY is already bytes."""
        # Save original key
        original_key = settings.OTP_SIGNING_KEY

        # Set key as bytes (not string)
        settings.OTP_SIGNING_KEY = Fernet.generate_key()

        try:
            context = {"identifier": "test", "metadata": {"key": "value"}}
            encrypted = encrypt_context(context)

            assert encrypted is not None
            assert isinstance(encrypted, str)
        finally:
            # Restore original key
            settings.OTP_SIGNING_KEY = original_key

    def test_decrypt_context_with_bytes_key(self):
        """Test decryption when OTP_SIGNING_KEY is already bytes."""
        original_key = settings.OTP_SIGNING_KEY
        settings.OTP_SIGNING_KEY = Fernet.generate_key()

        try:
            context = {"identifier": "test123", "data": "value"}
            encrypted = encrypt_context(context)
            decrypted = decrypt_context(encrypted)

            assert context == decrypted
        finally:
            settings.OTP_SIGNING_KEY = original_key


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

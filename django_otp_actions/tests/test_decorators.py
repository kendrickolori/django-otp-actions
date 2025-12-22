import django
from django.conf import settings
from cryptography.fernet import Fernet
from freezegun import freeze_time
from datetime import datetime, timedelta

# Configure Django settings BEFORE importing DRF
if not settings.configured:
    settings.configure(
        DEBUG=True,
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            }
        },
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "rest_framework",
            "django_otp_actions",
        ],
        SECRET_KEY="test-secret-key",
        OTP_SIGNING_KEY=Fernet.generate_key(),
        REST_FRAMEWORK={},
    )
    django.setup()

# NOW import DRF components and decorators
from django_otp_actions.decorators import otp_protected, verify_otp
from django_otp_actions.services import generate_otp


class MockRequest:
    """Simple mock request object that mimics DRF Request"""

    def __init__(self, data=None):
        self.data = data or {}
        self.META = {}
        self.method = "POST"


# Test data
IDENTIFIER = "test@example.com"
METADATA = {"email": "user@example.com", "phone": "+1234567890", "name": "Test User"}


class TestOTPProtectedDecorator:
    """Test otp_protected decorator."""

    def test_injects_generate_otp_function(self):
        """Decorator should inject generate_otp into request."""
        request = MockRequest()

        @otp_protected()
        def view(request):
            return request

        result = view(request)

        assert hasattr(result, "generate_otp")
        assert callable(result.generate_otp)

    def test_generate_otp_returns_valid_data(self):
        """Injected generate_otp should return valid OTP and context."""
        request = MockRequest()

        @otp_protected()
        def view(request):
            otp, context = request.generate_otp(IDENTIFIER, METADATA)
            return otp, context

        otp, context = view(request)

        assert otp is not None
        assert len(otp) == 6
        assert otp.isdigit()
        assert context is not None
        assert isinstance(context, str)

    def test_preserves_function_metadata(self):
        """Decorator should preserve original function name and docstring."""

        @otp_protected()
        def my_view(request):
            """My view docstring."""
            pass

        assert my_view.__name__ == "my_view"
        assert my_view.__doc__ == "My view docstring."

    def test_passes_through_args_and_kwargs(self):
        """Decorator should pass through additional args and kwargs."""
        request = MockRequest()

        @otp_protected()
        def view(request, arg1, arg2, kwarg1=None):
            return arg1, arg2, kwarg1

        result = view(request, "a", "b", kwarg1="c")

        assert result == ("a", "b", "c")


class TestVerifyOTPDecorator:
    """Test verify_otp decorator."""

    @freeze_time("2024-12-20 10:00:00")
    def test_valid_otp_passes(self):
        """Valid OTP should pass verification and inject context."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)
        request = MockRequest(data={"otp": otp, "context": encrypted_context})

        @verify_otp()
        def view(request):
            return {"status": "success"}

        result = view(request)

        assert result["status"] == "success"
        assert hasattr(request, "otp_verified")
        assert request.otp_verified is True
        assert hasattr(request, "otp_context")
        assert request.otp_context["identifier"] == IDENTIFIER

    @freeze_time("2024-12-20 10:00:00")
    def test_invalid_otp_returns_400(self):
        """Invalid OTP should return 400 with error and updated context."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)
        wrong_otp = "999999" if otp != "999999" else "111111"
        request = MockRequest(data={"otp": wrong_otp, "context": encrypted_context})

        @verify_otp()
        def view(request):
            return {"status": "success"}

        result = view(request)

        assert hasattr(result, "status_code")
        assert result.status_code == 400
        assert "error" in result.data
        assert "context" in result.data
        assert "Invalid OTP" in result.data["error"]

    @freeze_time("2024-12-20 10:00:00")
    def test_otp_expired_returns_410(self):
        """Expired OTP should return 410 with OTP_EXPIRED error code."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)
        request = MockRequest(data={"otp": otp, "context": encrypted_context})

        # Move time forward 6 minutes (past OTP expiry)
        with freeze_time("2024-12-20 10:06:00"):

            @verify_otp()
            def view(request):
                return {"status": "success"}

            result = view(request)

        assert hasattr(result, "status_code")
        assert result.status_code == 410
        assert result.data["error_code"] == "OTP_EXPIRED"
        assert "OTP has expired" in result.data["error"]

    @freeze_time("2024-12-20 10:00:00")
    def test_session_expired_returns_410(self):
        """Expired session should return 410 with SESSION_EXPIRED error code."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)
        request = MockRequest(data={"otp": otp, "context": encrypted_context})

        # Move time forward 16 minutes (past session expiry)
        with freeze_time("2024-12-20 10:16:00"):

            @verify_otp()
            def view(request):
                return {"status": "success"}

            result = view(request)

        assert hasattr(result, "status_code")
        assert result.status_code == 410
        assert result.data["error_code"] == "SESSION_EXPIRED"
        assert "Session has expired" in result.data["error"]

    @freeze_time("2024-12-20 10:00:00")
    def test_max_retries_exceeded_returns_429(self):
        """Exceeding max retries should return 429 with MAX_RETRIES_EXCEEDED."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA, max_retries=3)
        wrong_otp = "999999" if otp != "999999" else "111111"

        # Make 3 failed attempts
        for _ in range(3):
            request = MockRequest(data={"otp": wrong_otp, "context": encrypted_context})

            @verify_otp()
            def view(request):
                return {"status": "success"}

            result = view(request)
            if hasattr(result, "data") and "context" in result.data:
                encrypted_context = result.data["context"]

        # 4th attempt should fail with max retries exceeded
        request = MockRequest(data={"otp": wrong_otp, "context": encrypted_context})

        @verify_otp()
        def view(request):
            return {"status": "success"}

        result = view(request)

        assert hasattr(result, "status_code")
        assert result.status_code == 429
        assert result.data["error_code"] == "MAX_RETRIES_EXCEEDED"
        assert "Maximum retry attempts" in result.data["error"]

    def test_missing_otp_returns_400(self):
        """Missing OTP should return 400 with error message."""
        request = MockRequest(data={"context": "some_context"})

        @verify_otp()
        def view(request):
            return {"status": "success"}

        result = view(request)

        assert hasattr(result, "status_code")
        assert result.status_code == 400
        assert "OTP and context are required" in result.data["error"]

    def test_missing_context_returns_400(self):
        """Missing context should return 400 with error message."""
        request = MockRequest(data={"otp": "123456"})

        @verify_otp()
        def view(request):
            return {"status": "success"}

        result = view(request)

        assert hasattr(result, "status_code")
        assert result.status_code == 400
        assert "OTP and context are required" in result.data["error"]

    def test_missing_both_returns_400(self):
        """Missing both OTP and context should return 400."""
        request = MockRequest(data={})

        @verify_otp()
        def view(request):
            return {"status": "success"}

        result = view(request)

        assert hasattr(result, "status_code")
        assert result.status_code == 400
        assert "OTP and context are required" in result.data["error"]

    def test_invalid_encrypted_context_returns_400(self):
        """Invalid/corrupted context should return 400 with OTP_ERROR."""
        request = MockRequest(data={"otp": "123456", "context": "invalid_context"})

        @verify_otp()
        def view(request):
            return {"status": "success"}

        result = view(request)

        assert hasattr(result, "status_code")
        assert result.status_code == 400
        assert result.data["error_code"] == "OTP_ERROR"

    def test_preserves_function_metadata(self):
        """Decorator should preserve original function name and docstring."""

        @verify_otp()
        def my_verify_view(request):
            """My verify view docstring."""
            pass

        assert my_verify_view.__name__ == "my_verify_view"
        assert my_verify_view.__doc__ == "My verify view docstring."

    @freeze_time("2024-12-20 10:00:00")
    def test_passes_through_args_and_kwargs(self):
        """Decorator should pass through additional args and kwargs."""
        otp, encrypted_context = generate_otp(IDENTIFIER, METADATA)
        request = MockRequest(data={"otp": otp, "context": encrypted_context})

        @verify_otp()
        def view(request, arg1, arg2, kwarg1=None):
            return arg1, arg2, kwarg1

        result = view(request, "a", "b", kwarg1="c")

        assert result == ("a", "b", "c")


class TestDecoratorIntegration:
    """Test decorators working together."""

    @freeze_time("2024-12-20 10:00:00")
    def test_full_otp_flow(self):
        """Test complete flow: generate OTP, then verify it."""
        # Step 1: Generate OTP
        generate_request = MockRequest()

        @otp_protected()
        def generate_view(request):
            otp, context = request.generate_otp(IDENTIFIER, METADATA)
            return {"otp": otp, "context": context}

        generate_result = generate_view(generate_request)
        otp = generate_result["otp"]
        context = generate_result["context"]

        # Step 2: Verify OTP
        verify_request = MockRequest(data={"otp": otp, "context": context})

        @verify_otp()
        def verify_view(request):
            return {
                "status": "verified",
                "identifier": request.otp_context["identifier"],
                "metadata": request.otp_context["metadata"],
            }

        verify_result = verify_view(verify_request)

        assert verify_result["status"] == "verified"
        assert verify_result["identifier"] == IDENTIFIER
        assert verify_result["metadata"] == METADATA


class TestEdgeCases:
    """Test edge cases for decorators."""

    @freeze_time("2024-12-20 10:00:00")
    def test_empty_string_otp(self):
        """Empty string OTP should be treated as missing."""
        request = MockRequest(data={"otp": "", "context": "some_context"})

        @verify_otp()
        def view(request):
            return {"status": "success"}

        result = view(request)

        assert result.status_code == 400
        assert "OTP and context are required" in result.data["error"]

    @freeze_time("2024-12-20 10:00:00")
    def test_empty_string_context(self):
        """Empty string context should be treated as missing."""
        request = MockRequest(data={"otp": "123456", "context": ""})

        @verify_otp()
        def view(request):
            return {"status": "success"}

        result = view(request)

        assert result.status_code == 400
        assert "OTP and context are required" in result.data["error"]

    @freeze_time("2024-12-20 10:00:00")
    def test_otp_with_leading_zeros(self):
        """OTP with leading zeros should work correctly."""
        # Manually create OTP with leading zeros
        from django_otp_actions.services import encrypt_context, decrypt_context

        otp_with_zeros = "000123"
        _, encrypted_context = generate_otp(IDENTIFIER, METADATA)
        context = decrypt_context(encrypted_context)
        context["code"] = otp_with_zeros
        encrypted_context = encrypt_context(context)

        request = MockRequest(
            data={"otp": otp_with_zeros, "context": encrypted_context}
        )

        @verify_otp()
        def view(request):
            return {"status": "success"}

        result = view(request)

        assert result["status"] == "success"


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])

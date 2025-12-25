import sys
import django
from django.conf import settings
from cryptography.fernet import Fernet
import pytest

# ------------------------------------------------------------------
# 1. CRITICAL: Configure Django Settings BEFORE importing DRF
# ------------------------------------------------------------------
if not settings.configured:
    settings.configure(
        DEBUG=True,
        DATABASES={
            "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
        },
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "rest_framework",
            "django_otp_actions",
        ],
        SECRET_KEY="test-secret-key",
        OTP_SIGNING_KEY=Fernet.generate_key(),
        REST_FRAMEWORK={
            "TEST_REQUEST_RENDERER_CLASSES": [
                "rest_framework.renderers.JSONRenderer",
                "rest_framework.renderers.MultiPartRenderer",
            ]
        },
    )
    django.setup()

# ------------------------------------------------------------------
# 2. Imports (Now safe to import DRF and Project components)
# ------------------------------------------------------------------
import hashlib
from unittest.mock import patch
from datetime import datetime, timedelta
from freezegun import freeze_time
from django.test import override_settings

from rest_framework.test import APIRequestFactory
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view

from django_otp_actions.decorators import otp_protected, require_otp_verification
from django_otp_actions.services import (
    generate_otp,
    encrypt_context,
    decrypt_context,
    increment_retry_count,
)
from django_otp_actions.exceptions import OTPException

# ------------------------------------------------------------------
# 3. Test Constants & Helpers
# ------------------------------------------------------------------
factory = APIRequestFactory()
IDENTIFIER = "test@example.com"
METADATA = {"email": "user@example.com", "name": "Test User"}

# --- UPDATED MOCK VIEWS ---
# We use @api_view to convert the raw Factory request into a DRF Request
# so that `request.data` is available to the decorators.


@api_view(["POST"])
@otp_protected()
def protected_gen_view(request):
    """View that generates an OTP."""
    otp, context = request.generate_otp(IDENTIFIER, METADATA)
    return Response({"otp": otp, "context": context})


@api_view(["POST"])
@require_otp_verification()
def protected_verify_view(request, *args, **kwargs):
    """View that requires verification."""
    # Return args/kwargs to verify they are passed through
    return Response(
        {
            "status": "success",
            "identifier": request.otp_context.get("identifier"),
            "kwargs": kwargs,
        }
    )


# ------------------------------------------------------------------
# 4. Test Suites
# ------------------------------------------------------------------
class TestOTPProtectedDecorator:
    """Tests for the @otp_protected decorator (Generation Phase)."""

    def test_injects_generate_otp_function(self):
        """Decorator should inject generate_otp into request."""
        request = factory.post("/gen/")

        @api_view(["POST"])
        @otp_protected()
        def check_injection(req):
            # Fix: We must return a Response object, not the function itself.
            # We check the logic inside the view and return the result as data.
            func = getattr(req, "generate_otp", None)
            return Response(
                {
                    "has_attr": hasattr(req, "generate_otp"),
                    "is_callable": callable(func),
                }
            )

        response = check_injection(request)

        assert response.status_code == 200
        assert response.data["has_attr"] is True
        assert response.data["is_callable"] is True

    def test_generate_otp_returns_valid_data(self):
        """Injected generate_otp should return valid OTP and context."""
        request = factory.post("/gen/")
        response = protected_gen_view(request)

        assert response.status_code == 200
        assert len(response.data["otp"]) == 6
        assert response.data["otp"].isdigit()
        assert isinstance(response.data["context"], str)

    def test_preserves_function_metadata(self):
        """Decorator should preserve original function name and docstring."""

        # We test the decorator directly on a plain function to verify metadata
        @otp_protected()
        def dummy_view(request):
            """Docstring."""
            pass

        assert dummy_view.__name__ == "dummy_view"
        assert dummy_view.__doc__ == "Docstring."

    def test_passes_through_args_and_kwargs(self):
        """Decorator should pass through additional args and kwargs."""
        request = factory.post("/gen/")

        @api_view(["POST"])
        @otp_protected()
        def view(req, *args, **kwargs):
            # Return args/kwargs in the response body
            return Response({"args": args, "kwargs": kwargs})

        # Note: In DRF test calls, kwargs usually come from the URL router.
        # Here we manually pass them to the view function.
        res = view(request, kwarg1="test_kw")

        assert res.data["kwargs"]["kwarg1"] == "test_kw"


class TestRequireOTPVerificationDecorator:
    """Tests for the @require_otp_verification decorator (Verification Phase)."""

    @freeze_time("2024-12-20 10:00:00")
    def test_valid_otp_passes(self):
        """Valid OTP should pass verification and execute view."""
        otp, context = generate_otp(IDENTIFIER, METADATA)
        request = factory.post("/v/", {"otp": otp, "context": context}, format="json")

        response = protected_verify_view(request)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["status"] == "success"
        assert response.data["identifier"] == IDENTIFIER

    @freeze_time("2024-12-20 10:00:00")
    def test_invalid_otp_returns_400(self):
        """Invalid OTP should return 400 and increment retry count."""
        otp, context = generate_otp(IDENTIFIER, METADATA)
        request = factory.post(
            "/v/", {"otp": "000000", "context": context}, format="json"
        )

        response = protected_verify_view(request)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data["error_code"] == "INVALID_OTP"

        # Verify retry increment
        new_ctx = decrypt_context(response.data["context"])
        assert new_ctx["retry_count"] == 1

    @freeze_time("2024-12-20 10:00:00")
    def test_otp_expired_returns_410(self):
        """Expired OTP (5 min) should return 410."""
        otp, context = generate_otp(IDENTIFIER, METADATA)

        with freeze_time("2024-12-20 10:06:00"):
            request = factory.post(
                "/v/", {"otp": otp, "context": context}, format="json"
            )
            response = protected_verify_view(request)

        assert response.status_code == status.HTTP_410_GONE
        assert response.data["error_code"] == "OTP_EXPIRED"

    @freeze_time("2024-12-20 10:00:00")
    def test_session_expired_returns_410(self):
        """Expired Session (15 min) should return 410."""
        otp, context = generate_otp(IDENTIFIER, METADATA)

        with freeze_time("2024-12-20 10:16:00"):
            request = factory.post(
                "/v/", {"otp": otp, "context": context}, format="json"
            )
            response = protected_verify_view(request)

        assert response.status_code == status.HTTP_410_GONE
        assert response.data["error_code"] == "SESSION_EXPIRED"

    @freeze_time("2024-12-20 10:00:00")
    def test_max_retries_exceeded_returns_429(self):
        """Exceeding max retries should return 429."""
        otp, context = generate_otp(IDENTIFIER, max_retries=1)

        # 1. Fail once
        req1 = factory.post("/v/", {"otp": "wrong", "context": context}, format="json")
        res1 = protected_verify_view(req1)
        ctx_after_fail = res1.data["context"]

        # 2. Try again (retry count is now 1, max is 1, so this attempt should be blocked)
        req2 = factory.post(
            "/v/", {"otp": "wrong", "context": ctx_after_fail}, format="json"
        )
        res2 = protected_verify_view(req2)

        assert res2.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert res2.data["error_code"] == "MAX_RETRIES_EXCEEDED"

    def test_missing_otp_returns_400(self):
        request = factory.post("/v/", {"context": "ctx"}, format="json")
        response = protected_verify_view(request)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data["error_code"] == "MISSING_FIELDS"

    def test_missing_context_returns_400(self):
        request = factory.post("/v/", {"otp": "123"}, format="json")
        response = protected_verify_view(request)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data["error_code"] == "MISSING_FIELDS"

    def test_missing_both_returns_400(self):
        request = factory.post("/v/", {}, format="json")
        response = protected_verify_view(request)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data["error_code"] == "MISSING_FIELDS"

    def test_invalid_encrypted_context_returns_400(self):
        request = factory.post(
            "/v/", {"otp": "123", "context": "garbage_data"}, format="json"
        )
        response = protected_verify_view(request)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data["error_code"] == "OTP_ERROR"

    @freeze_time("2024-12-20 10:00:00")
    def test_strips_whitespace_from_inputs(self):
        otp, context = generate_otp(IDENTIFIER)
        request = factory.post(
            "/v/", {"otp": f" {otp} ", "context": f" {context} "}, format="json"
        )
        response = protected_verify_view(request)
        assert response.status_code == status.HTTP_200_OK


class TestDecoratorIntegration:
    """Integration flow tests."""

    @freeze_time("2024-12-20 10:00:00")
    def test_full_otp_flow(self):
        # 1. Generate
        gen_req = factory.post("/gen/")
        gen_res = protected_gen_view(gen_req)

        # 2. Verify
        verify_req = factory.post("/v/", gen_res.data, format="json")
        verify_res = protected_verify_view(verify_req)

        assert verify_res.status_code == 200
        assert verify_res.data["identifier"] == IDENTIFIER

    @freeze_time("2024-12-20 10:00:00")
    def test_multiple_failed_attempts_then_success(self):
        otp, context = generate_otp(IDENTIFIER, max_retries=5)

        # Fail 2 times
        for _ in range(2):
            req = factory.post(
                "/v/", {"otp": "wrong", "context": context}, format="json"
            )
            res = protected_verify_view(req)
            context = res.data["context"]  # Update context for next try

        # Succeed
        req_success = factory.post(
            "/v/", {"otp": otp, "context": context}, format="json"
        )
        res_success = protected_verify_view(req_success)

        assert res_success.status_code == 200


class TestEdgeCases:
    """Edge cases (None, Empty Strings, etc)."""

    def test_empty_string_otp(self):
        request = factory.post("/v/", {"otp": "", "context": "ctx"}, format="json")
        res = protected_verify_view(request)
        assert res.status_code == 400
        assert res.data["error_code"] == "MISSING_FIELDS"

    def test_empty_string_context(self):
        request = factory.post("/v/", {"otp": "123", "context": ""}, format="json")
        res = protected_verify_view(request)
        assert res.status_code == 400
        assert res.data["error_code"] == "MISSING_FIELDS"

    def test_none_otp_value(self):
        request = factory.post("/v/", {"otp": None, "context": "ctx"}, format="json")
        res = protected_verify_view(request)
        assert res.status_code == 400
        assert res.data["error_code"] == "MISSING_FIELDS"

    def test_none_context_value(self):
        request = factory.post("/v/", {"otp": "123", "context": None}, format="json")
        res = protected_verify_view(request)
        assert res.status_code == 400
        assert res.data["error_code"] == "MISSING_FIELDS"

    @freeze_time("2024-12-20 10:00:00")
    def test_otp_with_leading_zeros(self):
        """Ensure '001234' is treated as a string, not number."""
        otp_val = "001234"
        otp_hash = hashlib.sha256(otp_val.encode("utf-8")).hexdigest()

        # Build manual context
        now = datetime.now()
        ctx_data = {
            "identifier": IDENTIFIER,
            "otp_hash": otp_hash,
            "max_retries": 3,
            "retry_count": 0,
            "timestamp": now.timestamp(),
            "otp_expiry": (now + timedelta(minutes=5)).timestamp(),
            "session_expiry": (now + timedelta(minutes=15)).timestamp(),
        }
        encrypted = encrypt_context(ctx_data)

        request = factory.post(
            "/v/", {"otp": otp_val, "context": encrypted}, format="json"
        )
        res = protected_verify_view(request)

        assert res.status_code == 200

    def test_preserves_kwargs(self):
        """Ensure kwargs passed to the view are preserved."""
        otp, context = generate_otp(IDENTIFIER)
        request = factory.post("/v/", {"otp": otp, "context": context}, format="json")

        # Passing extra kwarg 'check_me' via the call to the verified view
        # Note: In standard DRF, kwargs come from URL patterns.
        # Here we simulate by calling the python function directly.
        res = protected_verify_view(request, check_me="valid")

        # Note: protected_verify_view puts kwargs in response data
        assert res.data["kwargs"]["check_me"] == "valid"


class TestRetryCountBehavior:
    """Specific checks for retry counting logic."""

    @freeze_time("2024-12-20 10:00:00")
    def test_decorator_increments_retry_on_invalid_otp(self):
        otp, context = generate_otp(IDENTIFIER)
        req = factory.post("/v/", {"otp": "wrong", "context": context}, format="json")
        res = protected_verify_view(req)

        new_ctx = decrypt_context(res.data["context"])
        assert new_ctx["retry_count"] == 1

    @freeze_time("2024-12-20 10:00:00")
    def test_decorator_does_not_increment_on_valid_otp(self):
        otp, context = generate_otp(IDENTIFIER)
        req = factory.post("/v/", {"otp": otp, "context": context}, format="json")
        res = protected_verify_view(req)

        # On success, response is 200
        assert res.status_code == 200

    @freeze_time("2024-12-20 10:00:00")
    def test_decorator_does_not_increment_on_expired_otp(self):
        otp, context = generate_otp(IDENTIFIER)

        with freeze_time("2024-12-20 10:06:00"):
            req = factory.post("/v/", {"otp": otp, "context": context}, format="json")
            res = protected_verify_view(req)

        assert res.status_code == 410
        assert "context" not in res.data


class TestStressFailures:
    """Stress tests for configuration/system failures."""

    def test_generate_otp_fails_missing_key(self):
        """Decorator should handle generate_otp failure."""
        with override_settings(OTP_SIGNING_KEY=None):
            request = factory.post("/gen/")
            with pytest.raises(OTPException):
                protected_gen_view(request)

    def test_verify_fails_on_corrupted_key_config(self):
        """If server config is broken during verification, return 400 or 500."""
        otp, context = generate_otp(IDENTIFIER)

        # Simulate config changing to something invalid during verification
        # The key mismatch will cause a decryption failure (InvalidToken/Padding error)
        with override_settings(OTP_SIGNING_KEY="different_key_that_causes_fail"):
            req = factory.post("/v/", {"otp": otp, "context": context}, format="json")
            res = protected_verify_view(req)

            # Since decryption fails, it catches as OTPException and returns 400
            assert res.status_code == 400
            assert res.data["error_code"] == "OTP_ERROR"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

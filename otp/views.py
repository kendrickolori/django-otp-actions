from django_otp_actions.decorators import otp_protected, verify_otp
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
@api_view(["POST"])  # DRF must be outermost
@otp_protected()  # Then your custom decorator
def health(request):
    """Generate OTP for testing"""
    identifier = request.data.get("identifier", "test@example.com")
    otp, context = request.generate_otp(identifier=identifier)

    # In real app, send OTP via SMS/Email here
    print(f"OTP Code: {otp}")  # For testing only

    return Response(
        {
            "message": "OTP generated",
            "context": context,
            "otp": otp,  # Remove this in production!
        },
        status=status.HTTP_200_OK,
    )


@csrf_exempt
@api_view(["POST"])  # DRF outermost
@verify_otp()  # Then your custom decorator
def verify(request):
    """Verify OTP - only runs if OTP is valid"""
    return Response(
        {
            "message": "OTP verified successfully!",
            "identifier": request.otp_context.get("identifier"),
            "metadata": request.otp_context.get("metadata"),
        },
        status=status.HTTP_200_OK,
    )

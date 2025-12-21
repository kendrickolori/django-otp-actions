from .services import generate_otp, decrypt_context
from rest_framework.response import Response
from rest_framework import status


def otp_protected():
    def decorator(func):
        def wrapper(request, *args, **kwargs):
            request.generate_otp = generate_otp
            result = func(request, *args, **kwargs)
            return result

        return wrapper

    return decorator


def verify_otp():
    def decorator(func):
        def wrapper(request, *args, **kwargs):
            # Get OTP and context from request
            otp = str(request.data.get("otp", ""))
            encrypted_context = request.data.get("context", "")

            if not otp or not encrypted_context:
                return Response(
                    {"error": "OTP and context are required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                # Decrypt context
                context = decrypt_context(encrypted_context)

                # Verify OTP matches
                if otp != str(context["code"]):
                    return Response(
                        {"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST
                    )

                # TODO: Check expiration (timestamp)
                # TODO: Check identifier matches

                # OTP is valid - inject data into request
                request.otp_verified = True
                request.otp_context = context

                # Call the actual view
                return func(request, *args, **kwargs)

            except Exception as e:
                return Response(
                    {"error": "Invalid or expired OTP context"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        return wrapper

    return decorator

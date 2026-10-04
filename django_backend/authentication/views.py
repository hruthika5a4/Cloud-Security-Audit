import json
import random
import base64
import bcrypt
import datetime
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import User
from .utils import generate_jwt, jwt_required, send_otp_email, send_forgot_password_email


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(10)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def check_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


@csrf_exempt
def register_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
        email = data.get("email", "").strip()
        password = data.get("password", "").strip()
        name = data.get("name", "").strip()

        if not email or not password:
            return JsonResponse({"error": "Email and password are required"}, status=400)

        if User.objects.filter(email=email).exists():
            return JsonResponse({"error": "An account with this email already exists"}, status=400)

        password_hash = hash_password(password)
        otp = str(random.randint(100000, 999999))
        otp_expiry = timezone.now() + datetime.timedelta(minutes=15)

        user = User.objects.create(
            email=email,
            passwordHash=password_hash,
            name=name if name else email.split("@")[0],
            isVerified=False,
            otp=otp,
            otpExpiry=otp_expiry,
        )

        send_otp_email(email, otp)

        return JsonResponse({
            "success": True,
            "message": "OTP sent to email",
            "email": user.email
        }, status=201)

    except Exception as e:
        print(f"Registration Error: {e}")
        return JsonResponse({"error": "Server error during registration"}, status=500)


@csrf_exempt
def verify_otp_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
        email = data.get("email", "").strip()
        otp = data.get("otp", "").strip()

        if not email or not otp:
            return JsonResponse({"error": "Email and verification code are required"}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=404)

        if user.isVerified:
            return JsonResponse({"error": "Email is already verified"}, status=400)

        if not user.otp or user.otp != otp or not user.otpExpiry or timezone.now() > user.otpExpiry:
            return JsonResponse({"error": "Invalid or expired verification code"}, status=400)

        user.isVerified = True
        user.otp = None
        user.otpExpiry = None
        user.save()

        token = generate_jwt(user)

        return JsonResponse({
            "success": True,
            "token": token,
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "displayPicture": user.displayPicture
            }
        })

    except Exception as e:
        print(f"OTP Verification Error: {e}")
        return JsonResponse({"error": "Server error during verification"}, status=500)


@csrf_exempt
def login_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
        email = data.get("email", "").strip()
        password = data.get("password", "").strip()

        if not email or not password:
            return JsonResponse({"error": "Email and password are required"}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({"error": "Invalid credentials"}, status=400)

        if not check_password(password, user.passwordHash):
            return JsonResponse({"error": "Invalid credentials"}, status=400)

        if not user.isVerified:
            return JsonResponse({
                "error": "Please verify your email first. Contact support if you did not receive a code.",
                "requiresOtp": True,
                "email": user.email
            }, status=403)

        token = generate_jwt(user)

        return JsonResponse({
            "token": token,
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "displayPicture": user.displayPicture
            }
        })

    except Exception as e:
        print(f"Login Error: {e}")
        return JsonResponse({"error": "Server error during login"}, status=500)


@csrf_exempt
@jwt_required
def me_view(request):
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    user = request.user_obj
    return JsonResponse({
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "displayPicture": user.displayPicture
    })


@csrf_exempt
@jwt_required
def profile_view(request):
    if request.method != "PUT" and request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        user = request.user_obj

        # Process multipart/form-data or JSON
        name = request.POST.get("name")
        if not name and request.content_type == "application/json":
            try:
                body = json.loads(request.body.decode("utf-8") or "{}")
                name = body.get("name")
            except Exception:
                pass

        if name:
            user.name = name

        if "displayPicture" in request.FILES:
            uploaded_file = request.FILES["displayPicture"]
            file_bytes = uploaded_file.read()
            b64 = base64.b64encode(file_bytes).decode("utf-8")
            content_type = uploaded_file.content_type or "image/png"
            user.displayPicture = f"data:{content_type};base64,{b64}"

        user.save()

        return JsonResponse({
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "displayPicture": user.displayPicture
        })

    except Exception as e:
        print(f"Profile Update Error: {e}")
        return JsonResponse({"error": "Server error during profile update"}, status=500)


@csrf_exempt
def forgot_password_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
        email = data.get("email", "").strip()

        if not email:
            return JsonResponse({"error": "Email is required."}, status=400)

        user = User.objects.filter(email=email).first()
        if not user:
            return JsonResponse({"success": True, "message": "If this email is registered, an OTP has been sent."})

        otp = str(random.randint(100000, 999999))
        otp_expiry = timezone.now() + datetime.timedelta(minutes=15)

        user.otp = otp
        user.otpExpiry = otp_expiry
        user.save()

        send_forgot_password_email(email, otp)

        return JsonResponse({"success": True, "message": "If this email is registered, an OTP has been sent."})

    except Exception as e:
        print(f"Forgot Password Error: {e}")
        return JsonResponse({"error": "Server error. Please try again."}, status=500)


@csrf_exempt
def reset_password_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
        email = data.get("email", "").strip()
        otp = data.get("otp", "").strip()
        new_password = data.get("newPassword", "").strip()

        if not email or not otp or not new_password:
            return JsonResponse({"error": "Email, OTP, and new password are all required."}, status=400)

        if len(new_password) < 6:
            return JsonResponse({"error": "Password must be at least 6 characters."}, status=400)

        user = User.objects.filter(email=email).first()
        if not user:
            return JsonResponse({"error": "No account found with this email."}, status=404)

        if not user.otp or user.otp != otp or not user.otpExpiry or timezone.now() > user.otpExpiry:
            return JsonResponse({"error": "Invalid or expired reset code. Please request a new one."}, status=400)

        user.passwordHash = hash_password(new_password)
        user.otp = None
        user.otpExpiry = None
        user.save()

        return JsonResponse({"success": True, "message": "Password reset successfully. You can now log in."})

    except Exception as e:
        print(f"Reset Password Error: {e}")
        return JsonResponse({"error": "Server error. Please try again."}, status=500)

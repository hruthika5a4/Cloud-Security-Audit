import jwt
import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from django.conf import settings
from django.http import JsonResponse
from .models import User


def generate_jwt(user):
    payload = {
        "userId": user.id,
        "email": user.email,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def decode_jwt(token):
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None


def authenticate_jwt(request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")

    if not auth_header:
        return None, JsonResponse({"error": "Access denied. No token provided."}, status=401)

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None, JsonResponse({"error": "Invalid token header format."}, status=401)

    token = parts[1]
    decoded = decode_jwt(token)
    if not decoded or "userId" not in decoded:
        return None, JsonResponse({"error": "Invalid or expired token."}, status=403)

    user_id = decoded["userId"]
    try:
        user = User.objects.get(id=user_id)
        return user, None
    except User.DoesNotExist:
        return None, JsonResponse({"error": "User not found."}, status=404)


def jwt_required(view_func):
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        user, err_response = authenticate_jwt(request)
        if err_response:
            return err_response
        request.user_obj = user
        return view_func(request, *args, **kwargs)
    return wrapped


def send_otp_email(email, otp):
    try:
        if not settings.SMTP_USER or settings.SMTP_USER == 'your-email@gmail.com' or not settings.SMTP_PASS:
            print("--- DEVELOPMENT MODE: SMTP NOT CONFIGURED ---")
            print(f"Verification code for {email}: {otp}")
            print("---------------------------------------------")
            return True

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Security Audit - Verify Your Email"
        msg["From"] = f'"Security Audit" <{settings.SMTP_USER}>'
        msg["To"] = email

        html = f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #0f172a;">Security Audit</h2>
          <p>Thank you for registering. Please use the following 6-digit code to verify your email address:</p>
          <div style="font-size: 32px; font-weight: bold; letter-spacing: 4px; color: #ef4444; margin: 20px 0;">{otp}</div>
          <p>This code will expire in 15 minutes.</p>
          <hr style="border-top: 1px solid #eee; margin-top: 30px;" />
          <p style="font-size: 12px; color: #94a3b8;">If you didn't request this, you can safely ignore this email.</p>
        </div>
        """
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASS)
            server.sendmail(settings.SMTP_USER, [email], msg.as_string())

        print(f"Real OTP Email sent to: {email}")
        return True
    except Exception as e:
        print(f"SMTP failed to send OTP. Error: {e}")
        print("--- FALLBACK OTP ---")
        print(f"Verification code for {email}: {otp}")
        print("--------------------")
        return True


def send_forgot_password_email(email, otp):
    try:
        if not settings.SMTP_USER or settings.SMTP_USER == 'your-email@gmail.com' or not settings.SMTP_PASS:
            print("--- DEV MODE: Password Reset OTP ---")
            print(f"Reset OTP for {email}: {otp}")
            print("------------------------------------")
            return True

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "AuditScope — Password Reset Code"
        msg["From"] = f'"AuditScope Security" <{settings.SMTP_USER}>'
        msg["To"] = email

        html = f"""
          <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:520px;margin:0 auto;padding:32px;border:1px solid #e2e8f0;border-radius:12px;color:#334155;">
            <div style="margin-bottom:24px;">
              <span style="font-size:22px;font-weight:800;color:#0f172a;">Audit</span><span style="font-size:22px;font-weight:800;color:#4f46e5;">Scope</span>
            </div>
            <h2 style="margin:0 0 8px;color:#0f172a;font-size:20px;">Password Reset Request</h2>
            <p style="color:#64748b;font-size:14px;line-height:1.6;margin:0 0 24px;">Use the code below to reset your password. It expires in <strong>15 minutes</strong>.</p>
            <div style="background:#f1f5f9;border-radius:10px;padding:24px;text-align:center;margin-bottom:24px;">
              <div style="font-size:38px;font-weight:900;letter-spacing:10px;color:#4f46e5;">{otp}</div>
            </div>
            <p style="color:#94a3b8;font-size:12px;line-height:1.6;">If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>
          </div>
        """
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASS)
            server.sendmail(settings.SMTP_USER, [email], msg.as_string())

        print(f"[Auth] Password reset OTP sent to {email}")
        return True
    except Exception as e:
        print(f"SMTP failed to send reset email: {e}")
        print("--- FALLBACK RESET OTP ---")
        print(f"Reset OTP for {email}: {otp}")
        print("--------------------------")
        return True

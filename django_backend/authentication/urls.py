from django.urls import re_path
from .views import (
    register_view,
    verify_otp_view,
    login_view,
    me_view,
    profile_view,
    forgot_password_view,
    reset_password_view
)

urlpatterns = [
    re_path(r'^/register/?$', register_view, name='auth-register'),
    re_path(r'^/verify-otp/?$', verify_otp_view, name='auth-verify-otp'),
    re_path(r'^/login/?$', login_view, name='auth-login'),
    re_path(r'^/me/?$', me_view, name='auth-me'),
    re_path(r'^/profile/?$', profile_view, name='auth-profile'),
    re_path(r'^/forgot-password/?$', forgot_password_view, name='auth-forgot-password'),
    re_path(r'^/reset-password/?$', reset_password_view, name='auth-reset-password'),
]

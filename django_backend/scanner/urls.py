from django.urls import re_path
from .views import scan_gcp_view, scan_aws_view

urlpatterns = [
    re_path(r'^/gcp/?$', scan_gcp_view, name='scan-gcp'),
    re_path(r'^/aws/?$', scan_aws_view, name='scan-aws'),
]

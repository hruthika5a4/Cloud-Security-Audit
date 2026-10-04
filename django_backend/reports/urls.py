from django.urls import re_path
from .views import (
    download_pdf_view,
    export_excel_view,
    send_email_view,
    project_summary_view
)

urlpatterns = [
    re_path(r'^/download/?$', download_pdf_view, name='reports-download'),
    re_path(r'^/export-excel/?$', export_excel_view, name='reports-export-excel'),
    re_path(r'^/send/?$', send_email_view, name='reports-send'),
    re_path(r'^/project-summary/?$', project_summary_view, name='reports-project-summary'),
]

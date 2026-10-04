from django.urls import re_path
from .views import (
    schedules_list_create_view,
    schedule_toggle_view,
    schedule_delete_view,
    schedule_run_view
)

urlpatterns = [
    re_path(r'^/?$', schedules_list_create_view, name='schedules-list-create'),
    re_path(r'^/(?P<schedule_id>[^/]+)/toggle/?$', schedule_toggle_view, name='schedules-toggle'),
    re_path(r'^/(?P<schedule_id>[^/]+)/run/?$', schedule_run_view, name='schedules-run'),
    re_path(r'^/(?P<schedule_id>[^/]+)/?$', schedule_delete_view, name='schedules-delete'),
]

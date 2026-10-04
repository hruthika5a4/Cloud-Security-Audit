from django.urls import re_path
from .views import (
    projects_list_create_view,
    projects_all_view,
    project_detail_view,
    project_scans_view
)

urlpatterns = [
    re_path(r'^/?$', projects_list_create_view, name='projects-list-create'),
    re_path(r'^/all/?$', projects_all_view, name='projects-all'),
    re_path(r'^/all/scans/?$', project_scans_view, {'project_id': 'all'}, name='projects-all-scans'),
    re_path(r'^/(?P<project_id>[^/]+)/scans/?$', project_scans_view, name='project-scans'),
    re_path(r'^/(?P<project_id>[^/]+)/?$', project_detail_view, name='project-detail'),
]

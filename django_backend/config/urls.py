from django.contrib import admin
from django.urls import re_path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse


def root_view(request):
    return JsonResponse({
        'status': 'ok',
        'message': 'Security Audit Accelerator Django Backend is running.',
        'version': '1.0.0',
        'healthCheck': '/api/health',
        'admin': '/admin/'
    })


def health_check(request):
    return JsonResponse({'status': 'ok', 'message': 'Security Audit API is running.'})


urlpatterns = [
    re_path(r'^$', root_view, name='root'),
    re_path(r'^admin/', admin.site.urls),
    re_path(r'^api/health/?$', health_check, name='health-check'),
    re_path(r'^api/auth', include('authentication.urls')),
    re_path(r'^api/projects', include('projects.urls')),
    re_path(r'^api/scan', include('scanner.urls')),
    re_path(r'^api/reports', include('reports.urls')),
    re_path(r'^api/schedules', include('automation.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

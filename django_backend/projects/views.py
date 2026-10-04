import json
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from authentication.utils import jwt_required
from .models import Project, ScanHistory


@csrf_exempt
@jwt_required
def projects_list_create_view(request):
    user = request.user_obj

    if request.method == "POST":
        try:
            data = json.loads(request.body.decode("utf-8") or "{}")
            name = data.get("name", "").strip()
            provider = data.get("provider", "").strip()

            if not name or not provider:
                return JsonResponse({"error": "Project name and provider are required."}, status=400)

            project = Project.objects.create(
                name=name,
                provider=provider,
                user=user
            )

            return JsonResponse(project.to_dict(), status=201)
        except Exception as e:
            print(f"Error creating project: {e}")
            return JsonResponse({"error": "Failed to create project."}, status=500)

    elif request.method == "GET":
        try:
            projects = Project.objects.filter(user=user).order_by("-createdAt")
            projects_data = [p.to_dict(include_scans_count=True) for p in projects]
            return JsonResponse(projects_data, safe=False)
        except Exception as e:
            print(f"Error fetching projects: {e}")
            return JsonResponse({"error": "Failed to fetch projects."}, status=500)

    return JsonResponse({"error": "Method not allowed"}, status=405)


@csrf_exempt
@jwt_required
def projects_all_view(request):
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        user = request.user_obj
        projects = Project.objects.filter(user=user).order_by("-createdAt")
        projects_data = [p.to_dict(include_scans_count=False) for p in projects]
        return JsonResponse(projects_data, safe=False)
    except Exception as e:
        print(f"Error fetching project list: {e}")
        return JsonResponse({"error": "Failed to fetch project list."}, status=500)


@csrf_exempt
@jwt_required
def project_detail_view(request, project_id):
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        user = request.user_obj
        project = Project.objects.filter(id=project_id, user=user).first()
        if not project:
            return JsonResponse({"error": "Project not found or access denied."}, status=404)

        return JsonResponse(project.to_dict(include_scans_count=True))
    except Exception as e:
        print(f"Error fetching project: {e}")
        return JsonResponse({"error": "Failed to fetch project."}, status=500)


@csrf_exempt
@jwt_required
def project_scans_view(request, project_id):
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        user = request.user_obj

        if project_id == "all":
            scans = ScanHistory.objects.filter(project__user=user).select_related("project").order_by("-createdAt")
        else:
            project = Project.objects.filter(id=project_id, user=user).first()
            if not project:
                return JsonResponse({"error": "Project not found or access denied."}, status=404)
            scans = ScanHistory.objects.filter(project=project).select_related("project").order_by("-createdAt")

        formatted_scans = [s.to_dict(include_project=True, parse_findings=True) for s in scans]
        return JsonResponse(formatted_scans, safe=False)

    except Exception as e:
        print(f"Error fetching scan history: {e}")
        return JsonResponse({"error": "Failed to fetch scan history."}, status=500)

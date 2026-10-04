import json
import threading
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.utils import timezone
from authentication.utils import jwt_required
from projects.models import Project
from .models import AuditSchedule
from .services.scheduler import (
    compute_next_run,
    ensure_project_linked,
    run_gcp_scan,
    run_aws_scan,
    send_audit_email
)


def _trigger_background_scan(schedule_id):
    try:
        schedule = AuditSchedule.objects.filter(id=schedule_id).select_related('project', 'user').first()
        if not schedule:
            return

        creds_source = schedule.credentials or (schedule.project.credentials if schedule.project else None)
        if not creds_source:
            return

        resolved_project_id = ensure_project_linked(schedule, creds_source)
        if not resolved_project_id:
            return

        provider = schedule.project.provider if schedule.project else 'gcp'
        scan_res = None
        if provider == 'gcp':
            scan_res = run_gcp_scan(creds_source, resolved_project_id)
        elif provider == 'aws':
            scan_res = run_aws_scan(creds_source, resolved_project_id)

        if scan_res:
            target = schedule.targetEmail or schedule.user.email
            proj_name = schedule.project.name if schedule.project else 'Automated Scan'
            send_audit_email(target, scan_res, proj_name)

            schedule.lastRun = timezone.now()
            schedule.save()
    except Exception as e:
        print(f"[Background Scan Error for {schedule_id}]: {e}")


@csrf_exempt
@jwt_required
def schedules_list_create_view(request):
    user = request.user_obj

    if request.method == "POST":
        try:
            data = json.loads(request.body.decode("utf-8") or "{}")
            project_id = data.get("projectId")
            provider = data.get("provider", "gcp")
            credentials = data.get("credentials")
            frequency = data.get("frequency")
            time_val = data.get("time")
            days_of_week = data.get("daysOfWeek", [])
            day_of_month = data.get("dayOfMonth")
            tz_offset = data.get("timezoneOffset", 0)
            target_email = data.get("targetEmail")

            if not frequency or not time_val:
                return JsonResponse({"error": "Frequency and time are required."}, status=400)

            next_run = compute_next_run(frequency, time_val, days_of_week, day_of_month, tz_offset)

            final_project_id = project_id
            if not final_project_id:
                proj_name = f"Automated {provider.upper()} Project"
                if provider == 'gcp' and credentials:
                    try:
                        p = json.loads(credentials) if isinstance(credentials, str) else credentials
                        if p.get("project_id"):
                            proj_name = p["project_id"]
                    except Exception:
                        pass
                elif provider == 'aws' and credentials:
                    try:
                        p = json.loads(credentials) if isinstance(credentials, str) else credentials
                        if p.get("accessKeyId"):
                            proj_name = f"AWS Project ({p['accessKeyId'][:6]}...)"
                    except Exception:
                        pass

                new_proj = Project.objects.create(
                    name=proj_name,
                    provider=provider,
                    credentials=credentials if isinstance(credentials, str) else json.dumps(credentials),
                    user=user
                )
                final_project_id = new_proj.id

            schedule = AuditSchedule.objects.create(
                frequency=frequency,
                time=time_val,
                daysOfWeek=days_of_week,
                dayOfMonth=day_of_month,
                credentials=credentials if isinstance(credentials, str) else (json.dumps(credentials) if credentials else None),
                nextRun=next_run,
                targetEmail=target_email,
                user=user,
                project_id=final_project_id
            )

            # Immediate first scan trigger in background thread
            threading.Thread(target=_trigger_background_scan, args=(schedule.id,), daemon=True).start()

            return JsonResponse(schedule.to_dict(include_project=True), status=201)

        except Exception as err:
            print(f"[Schedules] Create error: {err}")
            return JsonResponse({"error": "Failed to save schedule."}, status=500)

    elif request.method == "GET":
        try:
            schedules = AuditSchedule.objects.filter(user=user).select_related("project").order_by("-createdAt")
            return JsonResponse([s.to_dict(include_project=True) for s in schedules], safe=False)
        except Exception as err:
            print(f"[Schedules] Fetch error: {err}")
            return JsonResponse({"error": "Failed to fetch schedules."}, status=500)

    return JsonResponse({"error": "Method not allowed"}, status=405)


@csrf_exempt
@jwt_required
def schedule_toggle_view(request, schedule_id):
    if request.method != "PATCH" and request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        user = request.user_obj
        schedule = AuditSchedule.objects.filter(id=schedule_id, user=user).first()
        if not schedule:
            return JsonResponse({"error": "Schedule not found."}, status=404)

        schedule.isActive = not schedule.isActive
        schedule.save()
        return JsonResponse(schedule.to_dict(include_project=True))
    except Exception as err:
        print(f"[Schedules] Toggle error: {err}")
        return JsonResponse({"error": "Failed to toggle schedule."}, status=500)


@csrf_exempt
@jwt_required
def schedule_delete_view(request, schedule_id):
    if request.method != "DELETE":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        user = request.user_obj
        schedule = AuditSchedule.objects.filter(id=schedule_id, user=user).first()
        if not schedule:
            return JsonResponse({"error": "Schedule not found."}, status=404)

        schedule.delete()
        return JsonResponse({"message": "Schedule deleted successfully."})
    except Exception as err:
        print(f"[Schedules] Delete error: {err}")
        return JsonResponse({"error": "Failed to delete schedule."}, status=500)


@csrf_exempt
@jwt_required
def schedule_run_view(request, schedule_id):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        user = request.user_obj
        schedule = AuditSchedule.objects.filter(id=schedule_id, user=user).first()
        if not schedule:
            return JsonResponse({"error": "Schedule not found."}, status=404)

        threading.Thread(target=_trigger_background_scan, args=(schedule.id,), daemon=True).start()
        return JsonResponse({"message": "Manual audit triggered! Report will be sent to your email list momentarily."})
    except Exception as err:
        print(f"[Schedules] Run error: {err}")
        return JsonResponse({"error": "Failed to run schedule."}, status=500)

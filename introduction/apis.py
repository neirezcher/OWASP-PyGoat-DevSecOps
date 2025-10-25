import os
import requests
from hashlib import md5
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.conf import settings
from introduction.playground.A6.utility import check_vuln
from introduction.playground.ssrf import main
from introduction.playground.A9.main import Log
from .utility import ssrf_html_input_extractor



@csrf_exempt
@login_required(login_url="/login/")
@require_POST
def ssrf_code_checker(request):

    html_code = request.POST.get("html_code")

    if  not html_code:
        return JsonResponse({"status": "error", "message": "Missing code"}, status=400)

    test_bench1 = ssrf_html_input_extractor(html_code)
    if len(test_bench1) > 4:
        return JsonResponse({'message': 'Too many inputs in HTML. Try again'}, status=400)

    correct_output1 = [
        {"blog": "blog1-passed"},
        {"blog": "blog2-passed"},
        {"blog": "blog3-passed"},
        {"blog": "blog4-passed"},
    ]
    outputs = [main.ssrf_lab(inp) for inp in test_bench1]

    if outputs != correct_output1:
        return JsonResponse({'message': 'Testbench failed. Try again.'}, status=200)

    outputs = [main.ssrf_lab('secret.txt')]
    if outputs == [{"blog": "No blog found"}]:
        return JsonResponse({'message': 'Congratulations, secure code.', 'passed': 1}, status=200)

    return JsonResponse({'message': 'Testbench passed, but code is not secure.'}, status=200)


@csrf_exempt
@login_required(login_url="/login/")
@require_POST
def log_function_checker(request):
    csrf_token = request.POST.get("csrfmiddlewaretoken")
    log_code = request.POST.get("log_code")
    api_code = request.POST.get("api_code")

    if not log_code or not api_code:
        return JsonResponse({"message": "Missing required code inputs"}, status=400)

    base_dir = os.path.dirname(__file__)
    log_filename = os.path.join(base_dir, "playground/A9/main.py")
    api_filename = os.path.join(base_dir, "playground/A9/api.py")

    with open(log_filename, "w", encoding="utf-8") as f:
        f.write(log_code)
    with open(api_filename, "w", encoding="utf-8") as f:
        f.write(api_code)

    open("test.log", "w").close()  # clear file

    # Simulate requests to target
    target_url = request.build_absolute_uri("/2021/discussion/A9/target")
    for method in ["GET", "POST", "PATCH", "DELETE"]:
        try:
            requests.request(method, target_url)
        except Exception:
            continue

    with open("test.log", "r", encoding="utf-8") as f:
        lines = f.readlines()

    return JsonResponse({"message": "success", "logs": lines}, status=200)


@csrf_exempt
@require_POST
def A7_discussion_api(request):
    code = request.POST.get('code')
    if not code:
        return JsonResponse({"message": "missing code"}, status=400)

    patterns = [
        "AF_session_id.objects.get(session_id = cookie).delete()",
        "AF_session_id.objects.get(session_id=cookie).delete()"
    ]
    for p in patterns:
        if p in code:
            return JsonResponse({"message": "success"}, status=200)
    return JsonResponse({"message": "failure"}, status=400)


@csrf_exempt
def A6_discussion_api(request):
    test_bench = ["Pillow==8.0.0", "PyJWT==2.4.0", "requests==2.28.0", "Django==4.0.4"]
    try:
        result = check_vuln(test_bench)
        if result:
            return JsonResponse({"message": "success", "vulns": result}, status=200)
        return JsonResponse({"message": "failure"}, status=400)
    except Exception:
        return JsonResponse({"message": "failure"}, status=400)




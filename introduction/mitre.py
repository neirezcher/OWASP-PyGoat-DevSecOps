import datetime
import re
import subprocess
from hashlib import md5

import jwt
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password

from .models import CSRFUserTbl
import logging

# Mitre top1 | CWE:787
FLAG = "NOT_SUPPOSED_TO_BE_ACCESSED"
logger = logging.getLogger(__name__)

# ============ MITRE Pages ============ #

@login_required(login_url='/login/')
def mitre_top1(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top1.html')

@login_required(login_url='/login/')
def mitre_top2(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top2.html')

@login_required(login_url='/login/')
def mitre_top3(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top3.html')

@login_required(login_url='/login/')
def mitre_top4(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top4.html')

@login_required(login_url='/login/')
def mitre_top5(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top5.html')

@login_required(login_url='/login/')
def mitre_top6(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top6.html')

@login_required(login_url='/login/')
def mitre_top7(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top7.html')

@login_required(login_url='/login/')
def mitre_top8(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top8.html')

@login_required(login_url='/login/')
def mitre_top9(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top9.html')

@login_required(login_url='/login/')
def mitre_top10(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top10.html')

@login_required(login_url='/login/')
def mitre_top11(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top11.html')

@login_required(login_url='/login/')
def mitre_top12(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top12.html')

@login_required(login_url='/login/')
def mitre_top13(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top13.html')

@login_required(login_url='/login/')
def mitre_top14(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top14.html')

@login_required(login_url='/login/')
def mitre_top15(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top15.html')

@login_required(login_url='/login/')
def mitre_top16(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top16.html')

@login_required(login_url='/login/')
def mitre_top17(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top17.html')

@login_required(login_url='/login/')
def mitre_top18(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top18.html')

@login_required(login_url='/login/')
def mitre_top19(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top19.html')

@login_required(login_url='/login/')
def mitre_top20(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top20.html')

@login_required(login_url='/login/')
def mitre_top21(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top21.html')

@login_required(login_url='/login/')
def mitre_top22(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top22.html')

@login_required(login_url='/login/')
def mitre_top23(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top23.html')

@login_required(login_url='/login/')
def mitre_top24(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top24.html')

@login_required(login_url='/login/')
def mitre_top25(request):
    if request.method == 'GET':
        return render(request, 'mitre/mitre_top25.html')


# ============ CSRF LAB ============ #

@csrf_exempt
def csrf_lab_login(request):
    if request.method == 'GET':
        return render(request, 'mitre/csrf_lab_login.html')

    # POST
    username = (request.POST.get('username') or "").strip()
    password = (request.POST.get('password') or "").strip()

    if not username or not password:
        return redirect('/mitre/9/lab/login')

    try:
        user = CSRFUserTbl.objects.filter(username=username).first()
        if not user:
            # generic redirect for invalid credentials
            return redirect('/mitre/9/lab/login')

        stored = (user.password or "").strip()

        # 1 Preferred: stored value is a Django hashed password (pbkdf2 prefix)
        if stored.startswith("pbkdf2_") or stored.startswith("argon2$") or stored.startswith("bcrypt$"):
            if check_password(password, stored):
                authenticated = True
            else:
                authenticated = False
        else:
            # 2 Legacy support: if the stored value looks like an MD5 hex (32 hex chars),
            # validate MD5 and, on success, re-hash into Django's default hasher.
            if len(stored) == 32 and all(c in "0123456789abcdef" for c in stored.lower()):
                md5_hex = md5(password.encode()).hexdigest()
                if md5_hex == stored:
                    # successful legacy auth: re-hash password into pbkdf2
                    user.password = make_password(password)
                    user.save(update_fields=["password"])
                    authenticated = True
                else:
                    authenticated = False
            else:
                # unknown format: attempt check_password anyway (safe)
                authenticated = check_password(password, stored)

        if authenticated:
            payload = {
                'username': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=300),
                'iat': datetime.datetime.utcnow()
            }
            secret_key = getattr(settings, "JWT_SECRET_KEY", "csrf_vulnerability_key")
            token = jwt.encode(payload, secret_key, algorithm='HS256')

            response = redirect("/mitre/9/lab/transaction")
            # Set cookie — httponly + secure + samesite recommended (tests expect auth_cookiee)
            response.set_cookie(
                'auth_cookiee',
                token,
                httponly=True,
                secure=getattr(settings, "SESSION_COOKIE_SECURE", False),
                samesite='Strict',
                max_age=300
            )
            return response

        # fallback: invalid credentials (generic)
        return redirect('/mitre/9/lab/login')

    except Exception:
        logger.exception("Error during csrf_lab_login for username=%s", username)
        # avoid leaking internals
        return redirect('/mitre/9/lab/login')


@login_required(login_url='/login/')
@csrf_exempt
def csrf_transfer_monei(request):
    if request.method == 'GET':
        try:
            cookie = request.COOKIES.get('auth_cookiee')
            secret_key = getattr(settings, "JWT_SECRET_KEY", "csrf_vulnerability_key")
            payload = jwt.decode(cookie, secret_key, algorithms=['HS256'])
            username = payload['username']
            user = CSRFUserTbl.objects.filter(username=username).first()
            if not user:
                return redirect('/mitre/9/lab/login')
            return render(request, 'mitre/csrf_dashboard.html', {'balance': user.balance})
        except jwt.ExpiredSignatureError:
            return redirect('/mitre/9/lab/login')
        except jwt.InvalidTokenError:
            return redirect('/mitre/9/lab/login')
        except Exception:
            return redirect('/mitre/9/lab/login')


@login_required(login_url='/login/')
def csrf_transfer_monei_api(request, recipent, amount):
    if request.method == "GET":
        try:
            cookie = request.COOKIES.get('auth_cookiee')
            secret_key = getattr(settings, "JWT_SECRET_KEY", "csrf_vulnerability_key")
            payload = jwt.decode(cookie, secret_key, algorithms=['HS256'])
            username = payload['username']

            sender = CSRFUserTbl.objects.filter(username=username).first()
            recipient = CSRFUserTbl.objects.filter(username=recipent).first()

            if not sender or not recipient:
                return redirect('/mitre/9/lab/login')

            amt = int(amount)
            if 0 < amt <= sender.balance:
                sender.balance -= amt
                recipient.balance += amt
                sender.save()
                recipient.save()

            return redirect('/mitre/9/lab/transaction')
        except Exception:
            return redirect('/mitre/9/lab/login')
    return redirect('/mitre/9/lab/transaction')


# ============ LAB 25 ============ #

@login_required(login_url='/login/')
def mitre_lab_25(request):
    return render(request, 'mitre/mitre_lab_25.html')


@csrf_exempt
def mitre_lab_25_api(request):
    if request.method == "POST":
        expression = request.POST.get('expression', '')
        # Safe evaluation using limited globals
        try:
            if not re.match(r'^[0-9+\-*/().\s]+$', expression):
                return JsonResponse({'error': 'Invalid characters in expression'}, status=400)
            result = eval(expression, {"__builtins__": {}}, {})
            return JsonResponse({'result': result})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return redirect('/mitre/25/lab/')


# ============ LAB 17 ============ #

@login_required(login_url='/login/')
def mitre_lab_17(request):
    return render(request, 'mitre/mitre_lab_17.html')


def command_out(command_list):
    process = subprocess.Popen(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.communicate()


@csrf_exempt
def mitre_lab_17_api(request):
    if request.method == "POST":
        ip = request.POST.get('ip', '').strip()

        if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            return JsonResponse({'error': 'Invalid IP address format'}, status=400)

        # Safe execution without shell=True
        res, err = command_out(["nmap", ip])
        res, err = res.decode(), err.decode()

        ports = re.findall(r"(\d+/tcp\s+open\s+\S+)", res)
        return JsonResponse({'raw_res': res, 'raw_err': err, 'ports': ports})
    return redirect('/mitre/17/lab/')

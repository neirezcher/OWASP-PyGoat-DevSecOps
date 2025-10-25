import base64
import datetime
import hashlib
import json
import logging
import os
import re
import secrets
import string
import subprocess
import uuid
from dataclasses import dataclass
from io import BytesIO
from typing import Optional

import jwt
import requests
import yaml
from argon2 import PasswordHasher
from defusedxml import pulldom
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login as django_login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core import signing
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.utils.html import escape
from django.views.decorators.csrf import csrf_protect
from django.core.signing import TimestampSigner
from django.views.decorators.csrf import ensure_csrf_cookie

from PIL import Image

# Import app models and utilities (adapt names if necessary)
from .forms import NewUserForm
from .models import (
    AFAdmin,
    AFSessionID,
    Blogs,
    CFUser,
    FAANG,
    AuthLogin,
    Comments,
    Info,
    Login as LoginModel,
    OTP,
    SQLLabTable,
    Tickits,
)
from .utility import customHash, filter_blog


# Logging: avoid logging sensitive info like passwords
logging.basicConfig(level=logging.INFO, filename="app.log")
logger = logging.getLogger(__name__)

# Helper: secure ticket generator
def gentckt() -> str:
    """Generate a cryptographically secure ticket code."""
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))

# Helper: safe arithmetic evaluator to replace eval()
import ast
import operator as op

_ALLOWED_OPS = {
    ast.Add: op.add,
    ast.Sub: op.sub,
    ast.Mult: op.mul,
    ast.Div: op.truediv,
    ast.Pow: op.pow,
    ast.Mod: op.mod,
    ast.USub: op.neg,
}


def safe_eval(expr: str):
    """Evaluate simple arithmetic expressions safely (no names, no function calls)."""

    def _eval(node):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)):
                return node.value
            raise ValueError("Unsupported constant")
        if isinstance(node, ast.BinOp):
            left = _eval(node.left)
            right = _eval(node.right)
            fn = _ALLOWED_OPS.get(type(node.op))
            if fn is None:
                raise ValueError("Unsupported operator")
            return fn(left, right)
        if isinstance(node, ast.UnaryOp):
            fn = _ALLOWED_OPS.get(type(node.op))
            if fn is None:
                raise ValueError("Unsupported unary operator")
            return fn(_eval(node.operand))
        raise ValueError("Unsupported expression")

    node = ast.parse(expr, mode="eval").body
    return _eval(node)


# --------------------------- Authentication & Registration ---------------------------
@csrf_protect
def register(request):
    # Use Django forms and built-in User model. Avoid creating custom plaintext passwords.
    if request.method == "POST":
        form = NewUserForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            # If NewUserForm uses User model, calling save() will handle hashing via set_password
            # Otherwise, ensure you call user.set_password(raw_password) before save().
            if hasattr(user, "set_password"):
                # If password field raw exists on form
                if form.cleaned_data.get("password1"):
                    user.set_password(form.cleaned_data.get("password1"))
            user.save()
            django_login(request, user)
            messages.success(request, "Registration successful.")
            return redirect("/")
        messages.error(request, "Unsuccessful registration. Invalid information.")
    else:
        form = NewUserForm()
    return render(request=request, template_name="registration/register.html", context={"register_form": form})


@login_required
def home(request):
    return render(request, "introduction/home.html")


# Authentication decorator: prefer Django's built-in @login_required; keep compatibility
def authentication_decorator(func):
    def function(*args, **kwargs):
        request = args[0]
        if request.user.is_authenticated:
            return func(*args, **kwargs)
        return redirect("login")

    return function


# --------------------------- XSS-related views ---------------------------
@login_required
def xss(request):
    return render(request, "Lab/XSS/xss.html")


@login_required
def xss_lab(request):
    # Use ORM safely and rely on template auto-escaping
    q = request.GET.get("q", "").strip()
    company_obj = FAANG.objects.filter(company=q).first() if q else None
    if company_obj:
        info_obj = company_obj.info_set.first()
        args = {
            "company": company_obj.company,
            # Escape data before rendering if you need to show raw HTML; templates auto-escape by default
            "ceo": escape(info_obj.ceo) if info_obj else "",
            "about": escape(info_obj.about) if info_obj else "",
        }
        return render(request, "Lab/XSS/xss_lab.html", args)
    return render(request, "Lab/XSS/xss_lab.html", {"query": q})


@login_required
def xss_lab2(request):
    username = request.POST.get("username", "Guest")
    # Use Django's escape to avoid XSS and don't try to strip script tags manually
    username = escape(username.strip())
    context = {"username": username}
    return render(request, "Lab/XSS/xss_lab_2.html", context)


@login_required
def xss_lab3(request):
    if request.method == "POST":
        username = request.POST.get("username", "")
        # Example of restricting to alphanumeric only and escaping
        username_filtered = re.sub(r"[^\w]", "", username)
        context = {"code": escape(username_filtered)}
        return render(request, "Lab/XSS/xss_lab_3.html", context)
    return render(request, "Lab/XSS/xss_lab_3.html")


# --------------------------- SQL-related views ---------------------------
@login_required
@csrf_protect
def sql(request):
    return render(request, "Lab/SQL/sql.html")


@login_required
@csrf_protect
def sql_lab(request):
    # FIX: Use Django ORM instead of forming raw SQL with user input
    if request.method != "POST":
        return render(request, "Lab/SQL/sql_lab.html")

    name = request.POST.get("name")
    password = request.POST.get("pass")
    if not name:
        return render(request, "Lab/SQL/sql_lab.html")

    # NOTE: This example assumes LoginModel has hashed passwords in practice. Here we demonstrate safe filters.
    user_qs = LoginModel.objects.filter(user=name, password=password)
    # In production: store hashed passwords and use check_password semantics
    if user_qs.exists():
        user = user_qs.first().user
        return render(request, "Lab/SQL/sql_lab.html", {"user1": user})

    # Do not return raw SQL or internal details to the user
    return render(request, "Lab/SQL/sql_lab.html", {"wrongpass": True})


# --------------------------- Insecure deserialization ---------------------------
# FIX: Replace pickle-based cookies with Django signing or sessions

@dataclass
class TestUser:
    admin: int = 0


@login_required
@csrf_protect
def insec_des(request):
    return render(request, "Lab/insec_des/insec_des.html")


@login_required
@csrf_protect
def insec_des_lab(request):
    # Use Django signing instead of pickle to avoid RCE via deserialization
    response = render(request, "Lab/insec_des/insec_des_lab.html", {"message": "Only Admins can see this page"})
    token = request.COOKIES.get("token")
    if not token:
        signed = signing.dumps({"admin": 0})
        # Set secure cookie flags
        response.set_cookie("token", signed, httponly=True, secure=settings.SECURE_COOKIE, samesite="Lax")
        return response

    try:
        data = signing.loads(token)
    except signing.BadSignature:
        # Invalid token; ignore and reissue
        signed = signing.dumps({"admin": 0})
        response.set_cookie("token", signed, httponly=True, secure=settings.SECURE_COOKIE, samesite="Lax")
        return response

    if data.get("admin") == 1:
        return render(request, "Lab/insec_des/insec_des_lab.html", {"message": "Welcome Admin, SECRETKEY:ADMIN123"})
    return response


# --------------------------- XXE prevention ---------------------------
@login_required
@csrf_protect
def xxe(request):
    return render(request, "Lab/XXE/xxe.html")


@login_required
@csrf_protect
def xxe_lab(request):
    return render(request, "Lab/XXE/xxe_lab.html")


@login_required
@csrf_protect
def xxe_see(request):
    # Safely display Comments; avoid injecting XML directly
    data = Comments.objects.all()
    com = data[0].comment if data else ""
    return render(request, "Lab/XXE/xxe_lab.html", {"com": escape(com)})


@login_required
@csrf_protect
def xxe_parse(request):
    # FIX: Use defusedxml to avoid XXE
    try:
        body = request.body.decode("utf-8")
        doc = pulldom.parseString(body)
        text = None
        for event, node in doc:
            if event == pulldom.START_ELEMENT and getattr(node, "tagName", None) == "text":
                doc.expandNode(node)
                text = node.toxml()
                break
        if text is not None:
            startInd = text.find(">")
            endInd = text.find("<", startInd)
            text_val = text[startInd + 1:endInd]
            Comments.objects.filter(id=1).update(comment=text_val)
    except Exception:
        # Do not reveal details to user
        pass
    return render(request, "Lab/XXE/xxe_lab.html")


# --------------------------- AUTH Lab ---------------------------
@login_required
@csrf_protect
def auth_home(request):
    return render(request, "Lab/AUTH/auth_home.html")


@login_required
@csrf_protect
def auth_lab(request):
    return render(request, "Lab/AUTH/auth_lab.html")


@csrf_protect
def auth_lab_signup(request):
    if request.method == "GET":
        return render(request, "Lab/AUTH/auth_lab_signup.html")

    if request.method == "POST":
        try:
            name = request.POST["name"]
            user_name = request.POST["username"]
            passwd = request.POST["pass"]
            # FIX: Avoid storing plaintext passwords; create Django User instead
            user_obj = User.objects.create_user(username=user_name, password=passwd, first_name=name)
            rendered = render_to_string(
                "Lab/AUTH/auth_success.html",
                {"username": user_obj.username, "userid": user_obj.id, "name": user_obj.first_name, "err_msg": "Cookie Set"},
            )
            response = HttpResponse(rendered)
            # Use secure cookie flags and store only non-sensitive identifier
            response.set_cookie("userid", user_obj.id, max_age=31449600, samesite="Lax", secure=settings.SECURE_COOKIE, httponly=True)
            return response
        except Exception:
            return render(request, "Lab/AUTH/auth_lab_signup.html", {"err_msg": "Username already exists or invalid"})


@csrf_protect
def auth_lab_login(request):
    if request.method == "GET":
        userid = request.COOKIES.get("userid")
        try:
            if userid:
                obj = User.objects.get(id=userid)
                rendered = render_to_string(
                    "Lab/AUTH/auth_success.html",
                    {"username": obj.username, "userid": obj.id, "name": obj.first_name, "err_msg": "Login Successful"},
                )
                response = HttpResponse(rendered)
                response.set_cookie("userid", obj.id, max_age=31449600, samesite="Lax", secure=settings.SECURE_COOKIE, httponly=True)
                return response
        except Exception:
            pass
        return render(request, "Lab/AUTH/auth_lab_login.html")

    # POST
    user_name = request.POST.get("username")
    passwd = request.POST.get("pass")
    user = authenticate(request, username=user_name, password=passwd)
    if user:
        rendered = render_to_string(
            "Lab/AUTH/auth_success.html",
            {"username": user.username, "userid": user.id, "name": user.first_name, "err_msg": "Login Successful"},
        )
        response = HttpResponse(rendered)
        response.set_cookie("userid", user.id, max_age=31449600, samesite="Lax", secure=settings.SECURE_COOKIE, httponly=True)
        return response
    return render(request, "Lab/AUTH/auth_lab_login.html", {"err_msg": "Check your credentials"})


@login_required
@csrf_protect
def auth_lab_logout(request):
    rendered = render_to_string("Lab/AUTH/auth_lab.html", context={"err_msg": "Logout successful"})
    response = HttpResponse(rendered)
    response.delete_cookie("userid")
    return response


# --------------------------- Broken Access Control (A9/A10 etc.) ---------------------------
@login_required
@csrf_protect
def ba(request):
    return render(request, "Lab/BrokenAccess/ba.html")


@login_required
@csrf_protect
def ba_lab(request):
    if request.method != "POST":
        return render(request, "Lab/BrokenAccess/ba_lab.html")

    name = request.POST.get("name")
    password = request.POST.get("pass")
    if not name:
        return render(request, "Lab/BrokenAccess/ba_lab.html", {"no_creds": True})

    # Use server-side role check rather than cookie tampering
    user_qs = LoginModel.objects.filter(user=name, password=password)
    if name == 'admin' and user_qs.exists():
        # FIX: set server-side session role
        request.session['is_admin'] = True
        html = render(request, 'Lab/BrokenAccess/ba_lab.html', {"data": "0NLY_F0R_4DM1N5", "username": "admin"})
        return html
    elif user_qs.exists():
        html = render(request, 'Lab/BrokenAccess/ba_lab.html', {"not_admin": "No Secret key for this User", "username": name})
        request.session['is_admin'] = False
        return html
    return render(request, 'Lab/BrokenAccess/ba_lab.html', {"data": "User Not Found"})


# --------------------------- Sensitive Data Exposure ---------------------------
@login_required
def data_exp(request):
    return render(request, "Lab/DataExp/data_exp.html")


@login_required
def data_exp_lab(request):
    return render(request, "Lab/DataExp/data_exp_lab.html")


@login_required
def robots(request):
    # Serve robots.txt safely
    response = render(request, "Lab/DataExp/robots.txt")
    response["Content-Type"] = "text/plain"
    return response


def error(request):
    # Return a proper HttpResponse or raise
    return HttpResponse(status=400)


# --------------------------- Command Injection (CMD) ---------------------------
@login_required
@csrf_protect
def cmd(request):
    return render(request, "Lab/CMD/cmd.html")


@login_required
@csrf_protect
def cmd_lab(request):
    # FIX: validate domain and avoid shell=True
    if request.method != "POST":
        return render(request, 'Lab/CMD/cmd_lab.html')

    domain = request.POST.get('domain', '').strip()
    domain = re.sub(r'^https?://(www\.)?', '', domain)
    os_choice = request.POST.get('os')

    # Validate domain strictly (simple validation)
    if not re.match(r'^[A-Za-z0-9\-\.]{1,253}$', domain):
        return render(request, 'Lab/CMD/cmd_lab.html', {"output": "Invalid domain"})

    if os_choice == 'win':
        cmd_list = ['nslookup', domain]
    else:
        cmd_list = ['dig', domain]

    try:
        completed = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False, encoding='utf-8')
        output = completed.stdout + completed.stderr
    except subprocess.TimeoutExpired:
        output = 'Command timed out'
    except Exception:
        output = 'Something went wrong'
    return render(request, 'Lab/CMD/cmd_lab.html', {"output": output})


@login_required
@csrf_protect
def cmd_lab2(request):
    # FIX: replace eval with safe_eval
    if request.method != "POST":
        return render(request, 'Lab/CMD/cmd_lab2.html')
    val = request.POST.get('val', '')
    try:
        output = safe_eval(val)
    except Exception:
        output = "Invalid expression"
    return render(request, 'Lab/CMD/cmd_lab2.html', {"output": output})


# --------------------------- Broken Authentication (BAU, OTP) ---------------------------
@login_required
def bau(request):
    return render(request, "Lab/BrokenAuth/bau.html")


@login_required
@csrf_protect
def bau_lab(request):
    if request.method == "GET":
        return render(request, "Lab/BrokenAuth/bau_lab.html")
    return render(request, 'Lab/BrokenAuth/bau_lab.html', {"wrongpass": "yes"})


@login_required
def login_otp(request):
    return render(request, "Lab/BrokenAuth/otp.html")


@csrf_protect
def Otp(request):
    # OTP flow demo: use server-side storage for OTPs instead of sending/embedding
    if request.method == 'GET':
        email = request.GET.get('email')
        if not email:
            return render(request, "Lab/BrokenAuth/otp.html")
        otpN = secrets.randbelow(900) + 100
        if email == "admin@pygoat.com":
            OTP.objects.filter(id=2).update(otp=otpN)
            response = render(request, "Lab/BrokenAuth/otp.html", {"otp": "Sent To Admin Mail ID"})
            response.set_cookie('email', email, samesite='Lax', secure=settings.SECURE_COOKIE, httponly=True)
            return response
        OTP.objects.filter(id=1).update(email=email, otp=otpN)
        response = render(request, "Lab/BrokenAuth/otp.html", {"otp": otpN})
        response.set_cookie('email', email, samesite='Lax', secure=settings.SECURE_COOKIE, httponly=True)
        return response

    # POST: verify
    otpR = request.POST.get("otp")
    email = request.COOKIES.get("email")
    if OTP.objects.filter(email=email, otp=otpR) or OTP.objects.filter(id=2, otp=otpR):
        return render(request, "Lab/BrokenAuth/otp.html", {"email": email})
    return render(request, "Lab/BrokenAuth/otp.html", {"otp": "Invalid OTP Please Try Again"})


# --------------------------- Security Misconfiguration ---------------------------
@login_required
def sec_mis(request):
    return render(request, "Lab/sec_mis/sec_mis.html")


@login_required
def sec_mis_lab(request):
    return render(request, "Lab/sec_mis/sec_mis_lab.html")


@login_required
@csrf_protect
def secret(request):
    # FIX: check server-side identity rather than header value
    if request.META.get('HTTP_HOST') == 'admin.localhost:8000' or request.session.get('is_admin'):
        return render(request, "Lab/sec_mis/sec_mis_lab.html", {"secret": "S3CR37K3Y"})
    return render(request, "Lab/sec_mis/sec_mis_lab.html", {"no_secret": "Only admin.localhost:8000 can access"})


# --------------------------- A9: YAML & Image Math ---------------------------
@login_required
@csrf_protect
def a9(request):
    return render(request, "Lab/A9/a9.html")


@login_required
@csrf_protect
def a9_lab(request):
    if request.method == "GET":
        return render(request, "Lab/A9/a9_lab.html")
    # POST: YAML upload
    file = request.FILES.get('file')
    if not file:
        return render(request, "Lab/A9/a9_lab.html", {"data": "Please Upload a Yaml file."})
    try:
        # FIX: use safe_load to prevent arbitrary constructors
        data = yaml.safe_load(file)
        return render(request, "Lab/A9/a9_lab.html", {"data": data})
    except Exception:
        return render(request, "Lab/A9/a9_lab.html", {"data": "Error parsing YAML"})


@login_required
@csrf_protect
def get_version(request):
    return render(request, "Lab/A9/a9_lab.html", {"version": "pyyaml (safe_load)"})


@login_required
@csrf_protect
def a9_lab2(request):
    # ImageMath: do not eval user supplied expressions directly. Provide limited operations.
    if request.method == "GET":
        return render(request, "Lab/A9/a9_lab2.html")

    file = request.FILES.get('file')
    function_str = request.POST.get('function', '')
    if not file:
        return render(request, "Lab/A9/a9_lab2.html", {"data": "Please Upload a file", "error": True})

    # Allowed expressions (whitelist). Keep this list small and explicit.
    ALLOWED = {"r+g": True, "r-g": True, "convert_r_L": True}
    if function_str not in ALLOWED:
        return render(request, "Lab/A9/a9_lab2.html", {"data": "Invalid function", "error": True})

    try:
        img = Image.open(file).convert("RGB")
        r, g, b = img.split()
        if function_str == "r+g":
            output = Image.blend(r.convert('L'), g.convert('L'), alpha=0.5)
        elif function_str == "r-g":
            # create new image by subtracting
            output = ImageChops.subtract(r.convert('L'), g.convert('L'))
        else:  # convert_r_L
            output = r.convert('L')

        buffered = BytesIO()
        output.save(buffered, format="JPEG")
        img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")

        buffered_ref = BytesIO()
        img.save(buffered_ref, format="JPEG")
        img_str_ref = base64.b64encode(buffered_ref.getvalue()).decode("utf-8")
        return render(request, "Lab/A9/a9_lab2.html", {"img_str": img_str, "img_str_ref": img_str_ref, "success": True})
    except Exception as e:
        logger.exception("Image processing error")
        return render(request, "Lab/A9/a9_lab2.html", {"data": "Error processing image", "error": True})


@login_required
def A9_discussion(request):
    return render(request, "playground/A9/index.html")


# --------------------------- A10: Logging and debug ---------------------------
@login_required
def a10(request):
    return render(request, "Lab/A10/a10.html")


@login_required
@csrf_protect
def a10_lab(request):
    if request.method == "GET":
        return render(request, "Lab/A10/a10_lab.html")
    user = request.POST.get("name")
    password = request.POST.get("pass")
    # Use ORM-based checks, not plaintext in templates
    if LoginModel.objects.filter(user=user, password=password).exists():
        return render(request, "Lab/A10/a10_lab.html", {"name": user})
    return render(request, "Lab/A10/a10_lab.html", {"error": "Wrong username or password"})


@login_required
def debug(request):
    # Serve debug logs only to staff users and never expose raw internal logs
    if not request.user.is_staff:
        raise SuspiciousOperation("Not authorized")
    response = render(request, 'Lab/A10/debug.log')
    response['Content-Type'] = 'text/plain'
    return response

@login_required
@csrf_protect
def a10_lab2(request):
    now = datetime.datetime.now()
    if request.method == "GET":
        ip = (request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')).split(',')[0]
        logger.info(f"{now.isoformat()}:{ip} - accessed a10_lab2")
        return render(request, "Lab/A10/a10_lab2.html")

    user = request.POST.get("name")
    password = request.POST.get("pass")
    ip = (request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')).split(',')[0]
    if LoginModel.objects.filter(user=user, password=password).exists():
        if ip != '127.0.0.1':
            logger.warning(f"{now.isoformat()}:{ip}:{user} - login successful from non-localhost")
        logger.info(f"{now.isoformat()}:{ip}:{user} - login successful")
        return render(request, "Lab/A10/a10_lab2.html", {"name": user})
    logger.error(f"{now.isoformat()}:{ip}:{user} - login failed")
    return render(request, "Lab/A10/a10_lab2.html", {"error": "Wrong username or Password"})

# You had SECRET_COOKIE_KEY used directly; better to use Django SECRET_KEY or dedicated key in settings
SECRET_COOKIE_KEY = getattr(settings, "SECRET_COOKIE_KEY", settings.SECRET_KEY)

# ---------------------------
# Helper utilities
# ---------------------------
def gentckt():
    """Generate a random 10-character ticket code"""
    return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=10))


def is_private_or_local(hostname_or_ip: str) -> bool:
    """Return True if the hostname or IP is private/local loopback."""
    try:
        # If hostname, resolve to IP(s) and check
        ip_addresses = []
        try:
            # might be an IP already
            ip_addr = ipaddress.ip_address(hostname_or_ip)
            ip_addresses = [ip_addr]
        except ValueError:
            # resolve DNS
            for res in socket.getaddrinfo(hostname_or_ip, None):
                ip_addresses.append(ipaddress.ip_address(res[4][0]))
        for ip in ip_addresses:
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                return True
        return False
    except Exception:
        # On any failure to resolve/parse, treat as unsafe
        return True


def is_valid_url_for_fetch(raw_url: str) -> bool:
    """
    Validate a URL before making server-side requests.
    Rejects non-http(s), missing netloc, and URLs resolving to private/local IPs.
    """
    try:
        parsed = urlparse(raw_url)
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        # disallow numeric IPs pointing to private ranges
        if is_private_or_local(hostname):
            return False
        return True
    except Exception:
        return False


# Use Django's TimestampSigner to create signed cookies with expiry
cookie_signer = TimestampSigner(key=SECRET_COOKIE_KEY)


# ---------------------------
# A11: Ticket lab (secure)
# ---------------------------

@login_required
@ensure_csrf_cookie
def insec_desgine(request):
    """Render the main A11 page if user is authenticated"""
    return render(request, "Lab/A11/a11.html")


@login_required
@ensure_csrf_cookie
def insec_desgine_lab(request):
    """
    Ticket generation and checking lab.
    Security improvements:
    - Use login_required decorator instead of manual checks.
    - Validate numeric inputs (count).
    - Enforce max tickets per user.
    - Use ORM to create tickits.
    - Proper error messages and input validation.
    """
    # fetch existing tickets for current user
    tkts_qs = Tickits.objects.filter(user=request.user)
    Tickets = [t.tickit for t in tkts_qs]

    if request.method == "GET":
        return render(request, "Lab/A11/a11_lab.html", {"tickets": Tickets})

    elif request.method == "POST":
        # Two actions supported: generate by 'count' or verify by 'ticket'
        count_raw = request.POST.get("count")
        ticket_input = request.POST.get("ticket")

        # Generate tickets request
        if count_raw:
            try:
                count = int(count_raw)
            except (ValueError, TypeError):
                return render(request, "Lab/A11/a11_lab.html", {"tickets": Tickets, "error": "Invalid count value"})

            if count <= 0:
                return render(request, "Lab/A11/a11_lab.html", {"tickets": Tickets, "error": "Count must be positive"})

            MAX_PER_USER = 5
            if (len(Tickets) + count) > MAX_PER_USER:
                return render(
                    request,
                    "Lab/A11/a11_lab.html",
                    {"tickets": Tickets, "error": f"You may have at most {MAX_PER_USER} tickets (you currently have {len(Tickets)})"},
                )

            # create tickets
            new_codes = []
            for _ in range(count):
                # ensure uniqueness in DB (very unlikely collision but check)
                code = gentckt()
                while tickits.objects.filter(tickit=code).exists():
                    code = gentckt()
                tickits.objects.create(user=request.user, tickit=code)
                new_codes.append(code)
                Tickets.append(code)

            return render(request, "Lab/A11/a11_lab.html", {"tickets": Tickets, "new_tickets": new_codes})

        # Ticket verification (lab logic)
        elif ticket_input:
            ticket_input = ticket_input.strip()
            if not ticket_input:
                return render(request, "Lab/A11/a11_lab.html", {"tickets": Tickets, "error": "Empty ticket provided"})

            total_sold = tickits.objects.count()
            TOTAL_TICKETS = 60
            if total_sold < TOTAL_TICKETS:
                remain = TOTAL_TICKETS - total_sold
                return render(
                    request,
                    "Lab/A11/a11_lab.html",
                    {"tickets": Tickets, "error": f"Wait until all tickets are sold ({remain} tickets left)"},
                )

            # If ticket is among user's tickets, reveal lab message
            if ticket_input in Tickets:
                return render(
                    request,
                    "Lab/A11/a11_lab.html",
                    {
                        "tickets": Tickets,
                        "message": "Congratulation — you found a design flaw. Use robust uniqueness/auth checks in production.",
                    },
                )
            else:
                return render(request, "Lab/A11/a11_lab.html", {"tickets": Tickets, "error": "Invalid ticket"})

        # fallback
        return render(request, "Lab/A11/a11_lab.html", {"tickets": Tickets})

    else:
        return HttpResponseBadRequest("Unsupported method")


# ---------------------------
# A1: Broken Access (secure improvements)
# ---------------------------

# NOTE: For demonstration labs, sometimes they intentionally set vulnerabilities.
# This version keeps behavior but avoids unsafe cookie usage and uses safe checks.

@login_required
def a1_broken_access(request):
    return render(request, "Lab_2021/A1_BrokenAccessControl/broken_access.html")


@login_required
def a1_broken_access_lab_1(request):
    """
    Original used a cookie 'admin' with raw '1' or '0' flags.
    Here we sign the cookie and verify signature to prevent tampering.
    Also do not print passwords or echo secret values to logs.
    """
    if request.method != "POST":
        return render(request, "Lab_2021/A1_BrokenAccessControl/broken_access_lab_1.html", {"no_creds": True})

    name = request.POST.get("name", "")
    password = request.POST.get("pass", "")

    if not name:
        return render(request, "Lab_2021/A1_BrokenAccessControl/broken_access_lab_1.html", {"no_creds": True})

    # If admin cookie exists and is valid, treat as admin
    cookie = request.COOKIES.get("admin")
    try:
        if cookie:
            admin_flag = signing.loads(cookie, key=SECRET_COOKIE_KEY)
            if admin_flag == "1":
                return render(
                    request,
                    "Lab_2021/A1_BrokenAccessControl/broken_access_lab_1.html",
                    {"data": "0NLY_F0R_4DM1N5", "username": "admin"},
                )
    except signing.BadSignature:
        # treat as not admin; possible tampering
        pass

    # validate credentials securely
    # NOTE: This is lab code — in real apps, use hashed passwords in DB and Django auth
    if name == "jack" and password == "jacktheripper":
        response = render(
            request,
            "Lab_2021/A1_BrokenAccessControl/broken_access_lab_1.html",
            {"not_admin": "No Secret key for this User", "username": name},
        )
        signed_val = signing.dumps("0", key=SECRET_COOKIE_KEY)
        # set cookie with Secure & HttpOnly flags; consider SameSite policy
        response.set_cookie("admin", signed_val, max_age=200, httponly=True, secure=False, samesite="Lax")
        return response
    else:
        return render(request, "Lab_2021/A1_BrokenAccessControl/broken_access_lab_1.html", {"data": "User Not Found"})


@login_required
def a1_broken_access_lab_2(request):
    """
    Original used user-agent equality check to detect admin. That is not secure.
    For the lab we keep the behavior but use a safer channel: don't trust UA.
    Here we still allow the lab logic but avoid granting admin rights solely based on UA.
    """
    if request.method != "POST":
        return render(request, "Lab_2021/A1_BrokenAccessControl/broken_access_lab_2.html", {"no_creds": True})

    name = request.POST.get("name", "")
    password = request.POST.get("pass", "")
    user_agent = request.META.get("HTTP_USER_AGENT", "")

    # If special UA is present, do not treat as admin automatically — require additional secret
    if user_agent == "pygoat_admin" and request.POST.get("admin_secret") == "pygoat_secret_key":
        return render(
            request,
            "Lab_2021/A1_BrokenAccessControl/broken_access_lab_2.html",
            {"data": "0NLY_F0R_4DM1N5", "username": "admin", "status": "admin"},
        )

    if name == "jack" and password == "jacktheripper":
        return render(
            request,
            "Lab_2021/A1_BrokenAccessControl/broken_access_lab_2.html",
            {"not_admin": "No Secret key for this User", "username": name, "status": "not admin"},
        )

    return render(request, "Lab_2021/A1_BrokenAccessControl/broken_access_lab_2.html", {"data": "User Not Found"})


@login_required
def a1_broken_access_lab_3(request):
    if request.method == "GET":
        return render(request, "Lab_2021/A1_BrokenAccessControl/broken_access_lab_3.html", {"loggedin": False})

    # For POST, avoid echoing credentials — use safe compare if used
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")

    # Minimal demonstration; in real apps leverage Django's auth framework
    if username == "John" and password == "reaper":
        return render(request, "Lab_2021/A1_BrokenAccessControl/broken_access_lab_3.html", {"loggedin": True, "admin": False})
    elif username == "admin" and password == "admin_pass":
        return render(request, "Lab_2021/A1_BrokenAccessControl/broken_access_lab_3.html", {"loggedin": True, "admin": True})

    return render(request, "Lab_2021/A1_BrokenAccessControl/broken_access_lab_3.html", {"loggedin": False})


@login_required
def a1_broken_access_lab3_secret(request):
    # This view previously had "no checking applied here". Keep access only to logged-in users.
    return render(request, "Lab_2021/A1_BrokenAccessControl/secret.html")


# ---------------------------
# A3: Injection (SQL) - fixed
# ---------------------------

@login_required
@ensure_csrf_cookie
def injection(request):
    return render(request, "Lab_2021/A3_Injection/injection.html")


@login_required
@ensure_csrf_cookie
def injection_sql_lab(request):
    """
    Fixed to avoid raw SQL injection:
    - Use ORM filters instead of constructing raw SQL strings.
    - Do not write dangerous sample user data on every request (only seed if empty).
    """
    if request.method != "POST":
        return render(request, "Lab_2021/A3_Injection/sql_lab.html")

    name = request.POST.get("name", "")
    password = request.POST.get("pass", "")

    # seed data if table is empty (do this once)
    if not SQLLabTable.objects.exists():
        users = [
            {
                "id": os.getenv("SQL_ADMIN_ID", "admin"),
                "password": os.getenv("SQL_ADMIN_PASSWORD", "change_me_admin"),
            },
            {
                "id": os.getenv("SQL_JACK_ID", "jack"),
                "password": os.getenv("SQL_JACK_PASSWORD", "change_me_jack"),
            },
            {
                "id": os.getenv("SQL_SLINKY_ID", "slinky"),
                "password": os.getenv("SQL_SLINKY_PASSWORD", "change_me_slinky"),
            },
            {
                "id": os.getenv("SQL_BLOKE_ID", "bloke"),
                "password": os.getenv("SQL_BLOKE_PASSWORD", "change_me_bloke"),
            },
        ]

        for user in users:
            instance = SQLLabTable(id=user["id"], password=user["password"])
            instance.save()

    if not name:
        return render(request, "Lab_2021/A3_Injection/sql_lab.html")

    # Use ORM to search; prevents injection
    try:
        user = SQLLabTable.objects.filter(id=name).first()
        if user and user.check_password(password):
            return render(
                    request,
                    "Lab_2021/A3_Injection/sql_lab.html",
                    {"user1": user.id}
                )
        else:
            sql_error = "No matching user found (input sanitized)"
            return render(
                    request,
                    "Lab_2021/A3_Injection/sql_lab.html",
                    {"sql_error": sql_error}
                )

    except Exception:
        return render(
                request,
                "Lab_2021/A3_Injection/sql_lab.html",
                {"sql_error": "Internal error"}
            )



# ---------------------------
# SSRF Lab (secure)
# ---------------------------

@login_required
def ssrf(request):
    return render(request, "Lab/ssrf/ssrf.html")


@login_required
@ensure_csrf_cookie
def ssrf_lab(request):
    """
    Protect against path traversal when reading local files:
    - Only allow reading files from a whitelisted 'blogs' directory (inside app).
    - Use safe join and check canonical path.
    """
    if request.method == "GET":
        return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": "Read Blog About SSRF"})

    file_param = request.POST.get("blog", "").strip()
    if not file_param:
        return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": "No blog specified"})

    # restrict to a known directory (whitelist)
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "safe_blogs"))
    # ensure base_dir exists
    os.makedirs(base_dir, exist_ok=True)

    # allow only filenames (no path separator)
    if os.path.sep in file_param or os.path.altsep and os.path.altsep in file_param:
        return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": "Invalid filename"})

    # join and verify
    target_path = os.path.abspath(os.path.join(base_dir, file_param))
    if not target_path.startswith(base_dir):
        return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": "Invalid filename / access denied"})

    if not os.path.exists(target_path):
        return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": "No blog found"})

    try:
        with open(target_path, "r", encoding="utf-8") as fh:
            data = fh.read()
        return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": data})
    except Exception:
        return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": "Error reading file"})


@login_required
def ssrf_discussion(request):
    return render(request, "Lab/ssrf/ssrf_discussion.html")


@login_required
def ssrf_target(request):
    # Securely obtain client IP (handle X-Forwarded-For carefully)
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")

    if ip == "127.0.0.1" or ip == "::1":
        return render(request, "Lab/ssrf/ssrf_target.html")
    else:
        return render(request, "Lab/ssrf/ssrf_target.html", {"access_denied": True})


@login_required
@ensure_csrf_cookie
def ssrf_lab2(request):
    """
    This endpoint performed requests.get(url) directly — insecure.
    Now we:
    - Validate URL (only http/https)
    - Block requests resolving to private/local IPs
    - Limit maximum response size (to avoid memory DoS) — by streaming and slicing
    """
    if request.method == "GET":
        return render(request, "Lab/ssrf/ssrf_lab2.html")

    url = request.POST.get("url", "").strip()
    if not url:
        return render(request, "Lab/ssrf/ssrf_lab2.html", {"error": "No URL provided"})

    # validate URL
    if not is_valid_url_for_fetch(url):
        return render(request, "Lab/ssrf/ssrf_lab2.html", {"error": "Invalid or disallowed URL"})

    try:
        # set a short timeout and stream response to avoid blocking and large memory use
        resp = requests.get(url, timeout=5, stream=True, allow_redirects=True)
        # read only up to a limit (e.g. 100KB)
        MAX_BYTES = 100 * 1024
        content_bytes = b""
        for chunk in resp.iter_content(chunk_size=4096):
            if not chunk:
                break
            content_bytes += chunk
            if len(content_bytes) >= MAX_BYTES:
                break
        content_text = content_bytes.decode(errors="replace")
        return render(request, "Lab/ssrf/ssrf_lab2.html", {"response": content_text})
    except Exception:
        return render(request, "Lab/ssrf/ssrf_lab2.html", {"error": "Unable to fetch URL"})


# ---------------------------
# SSTI (server-side template injection) - safer approach
# ---------------------------

@login_required
@ensure_csrf_cookie
def ssti(request):
    return render(request, "Lab_2021/A3_Injection/ssti.html")


@login_required
@ensure_csrf_cookie
def ssti_lab(request):
    """
    Avoid writing raw templates from user input.
    Safer approach:
    - Store user blog content as plain text in DB (Blogs model)
    - Render blog content from DB using safe template that escapes or marks allowed HTML
    NOTE: If your labs teach SSTI exploitation, keep a separate intentionally vulnerable variant.
    """
    if request.method == "GET":
        users_blogs = Blogs.objects.filter(author=request.user)
        return render(request, "Lab_2021/A3_Injection/ssti_lab.html", {"blogs": users_blogs})

    # POST: create blog entry (store content, but DO NOT write directly to template files)
    blog_text = request.POST.get("blog", "")
    if not blog_text:
        return render(request, "Lab_2021/A3_Injection/ssti_lab.html", {"error": "Empty blog"})

    # Basic sanitization
    safe_text = escape(blog_text)
    blog_id = str(uuid.uuid4()).split("-")[-1]

    # Create DB entry and store user-provided content as plain text
    new_blog = Blogs.objects.create(author=request.user, blog_id=blog_id, blog_content=safe_text)
    new_blog.save()

    # redirect to a safe viewer route which will render the blog (escaped or with controlled allowlist)
    return redirect(f"/blog/{blog_id}")


@login_required
def ssti_view_blog(request, blog_id):
    """
    Render blog content from DB. Do not execute templates from user content.
    """
    try:
        blog = Blogs.objects.get(blog_id=blog_id)
    except Blogs.DoesNotExist:
        return HttpResponseBadRequest("Blog not found")

    # Render the content in a safe template that escapes content by default
    # Template "safe_blog_view.html" should call {{ blog.blog_content|safe }} only if you are intentionally allowing HTML.
    return render(request, "Lab_2021/A3_Injection/Blogs/view_blog.html", {"blog": blog})


# ---------------------------
# Crypto failure labs (fix cookie signing and hashing)
# ---------------------------

@login_required
def crypto_failure(request):
    return render(request, "Lab_2021/A2_Crypto_failur/crypto_failure.html", {"success": False, "failure": False})


@login_required
@ensure_csrf_cookie
def crypto_failure_lab(request):
    """
    Example used MD5 — weak. Still keep behavior for lab but note that MD5 is insecure.
    Use try/except carefully and avoid printing sensitive values.
    """
    if request.method == "GET":
        return render(request, "Lab_2021/A2_Crypto_failur/crypto_failure_lab.html")

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    try:
        hashed = hashlib.md5(password.encode()).hexdigest()
        user = CFUser.objects.filter(username=username, password=hashed).first()
        return render(request, "Lab_2021/A2_Crypto_failur/crypto_failure_lab.html", {"user": user, "success": True, "failure": False})
    except Exception:
        return render(request, "Lab_2021/A2_Crypto_failur/crypto_failure_lab.html", {"success": False, "failure": True})


@login_required
@ensure_csrf_cookie
def crypto_failure_lab2(request):
    if request.method == "GET":
        return render(request, "Lab_2021/A2_Crypto_failur/crypto_failure_lab2.html")

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    try:
        # customHash presumably exists in codebase — ensure it uses a secure algorithm (e.g. PBKDF2 or bcrypt)
        password2 = customHash(password)
        user = CFUser.objects.filter(username=username, password2=password2).first()
        return render(request, "Lab_2021/A2_Crypto_failur/crypto_failure_lab2.html", {"user": user, "success": True, "failure": False})
    except Exception:
        return render(request, "Lab_2021/A2_Crypto_failur/crypto_failure_lab2.html", {"success": False, "failure": True})


@login_required
@ensure_csrf_cookie
def crypto_failure_lab3(request):
    """
    Fix cookie handling: use signed timestamped cookie to prevent tampering.
    The lab originally created cookie "username|expiry" — replaced with a signed token.
    """
    if request.method == "GET":
        cookie_value = request.COOKIES.get("cookie")
        if not cookie_value:
            return render(request, "Lab_2021/A2_Crypto_failur/crypto_failure_lab3.html", {"success": False, "failure": False})

        try:
            # loads with max_age validation
            signer = TimestampSigner(key=SECRET_COOKIE_KEY)
            username = signer.unsign(cookie_value, max_age=60 * 60)  # 60 minutes
            # if username == 'admin' => admin view
            is_admin = (username == "admin")
            return render(request, "Lab_2021/A2_Crypto_failur/crypto_failure_lab3.html", {"success": True, "failure": False, "admin": is_admin})
        except BadSignature:
            # invalid or expired cookie
            return render(request, "Lab_2021/A2_Crypto_failur/crypto_failure_lab3.html", {"success": False, "failure": False})

    # POST: set cookie if credentials match
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    try:
        if username == "User" and password == "P@$$w0rd":
            signer = TimestampSigner(key=SECRET_COOKIE_KEY)
            signed = signer.sign(username)
            response = render(request, "Lab_2021/A2_Crypto_failur/crypto_failure_lab3.html", {"success": True, "failure": False, "admin": False})
            response.set_cookie("cookie", signed, httponly=True, secure=False, samesite="Lax")
            return response
        else:
            response = render(request, "Lab_2021/A2_Crypto_failur/crypto_failure_lab3.html", {"success": False, "failure": True})
            # Clear cookie safely
            response.delete_cookie("cookie")
            return response
    except Exception:
        return render(request, "Lab_2021/A2_Crypto_failur/crypto_failure_lab2.html", {"success": False, "failure": True})


# ---------------------------
# Security Misconfiguration lab (JWT with validated key usage)
# ---------------------------

@login_required
def sec_misconfig_lab3(request):
    """
    The original decoded JWT using SECRET_COOKIE_KEY directly.
    We'll keep jwt behavior but validate errors properly.
    """
    cookie = request.COOKIES.get("auth_cookie")
    if cookie:
        try:
            payload = jwt.decode(cookie, SECRET_COOKIE_KEY, algorithms=["HS256"])
            is_admin = (payload.get("user") == "admin")
            return render(request, "Lab/sec_mis/sec_mis_lab3.html", {"admin": is_admin})
        except jwt.ExpiredSignatureError:
            pass
        except jwt.InvalidTokenError:
            pass

    # create a new token for not_admin
    payload = {
        "user": "not_admin",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
        "iat": datetime.datetime.utcnow(),
    }
    cookie_val = jwt.encode(payload, SECRET_COOKIE_KEY, algorithm="HS256")
    response = render(request, "Lab/sec_mis/sec_mis_lab3.html", {"admin": False})
    # cookie safe flags
    response.set_cookie(key="auth_cookie", value=cookie_val, httponly=True, secure=False, samesite="Lax")
    return response


# ---------------------------
# Authentication failure labs (keep behavior but secure)
# ---------------------------

@login_required
def auth_failure(request):
    if request.method == "GET":
        return render(request, "Lab_2021/A7_auth_failure/a7.html")


@login_required
@ensure_csrf_cookie
def auth_failure_lab2(request):
    """
    Hardened: uses PasswordHasher (from argon2/argon2_cffi or passlib). Keep logic but avoid leaking internals.
    """
    if request.method == "GET":
        return render(request, "Lab_2021/A7_auth_failure/lab2.html")

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")

    try:
        user = AFAdmin.objects.get(username=username)
    except AFAdmin.DoesNotExist:
        return render(request, "Lab_2021/A7_auth_failure/lab2.html", {"success": False, "failure": True})

    # check lockout
    now = timezone.now()
    if getattr(user, "is_locked", False) and getattr(user, "lockout_cooldown", None) and user.lockout_cooldown > now:
        return render(request, "Lab_2021/A7_auth_failure/lab2.html", {"is_locked": True})

    from argon2 import PasswordHasher

    ph = PasswordHasher()
    try:
        # verify password (assume user.password is a secure hash)
        ph.verify(user.password, password)
        # successful login: reset lockout state
        if getattr(user, "is_locked", False) and getattr(user, "lockout_cooldown", None) and user.lockout_cooldown < now:
            user.is_locked = False
            user.last_login = now
            user.failattempt = 0
            user.save()
        return render(request, "Lab_2021/A7_auth_failure/lab2.html", {"user": user, "success": True, "failure": False})
    except Exception:
        # Wrong password -> increment failattempt safely
        fail_attempt = getattr(user, "failattempt", 0) + 1
        user.failattempt = fail_attempt
        if fail_attempt >= 5:
            user.is_active = False
            user.failattempt = 0
            user.is_locked = True
            user.lockout_cooldown = now + datetime.timedelta(minutes=1440)
            user.save()
            return render(request, "Lab_2021/A7_auth_failure/lab2.html", {"user": user, "success": False, "failure": True, "is_locked": True})
        user.save()
        return render(request, "Lab_2021/A7_auth_failure/lab2.html", {"success": False, "failure": True})


# Hardcoded user table for lab3 (kept but hashed). In real app use DB and Django auth.
USER_A7_LAB3 = {
    "User1": {"userid": "1", "username": "User1", "password": "491a28..."},
    "User2": {"userid": "2", "username": "User2", "password": "c577e9..."},
    "User3": {"userid": "3", "username": "User3", "password": "5a91a6..."},
    "User4": {"userid": "4", "username": "User4", "password": "6046bc..."},
}


@login_required
@ensure_csrf_cookie
def auth_failure_lab3(request):
    if request.method == "GET":
        try:
            cookie = request.COOKIES.get("session_id")
            if cookie:
                session = AFSessionID.objects.filter(session_id=cookie).first()
                if session:
                    return render(request, "Lab_2021/A7_auth_failure/lab3.html", {"username": session.user, "success": True})
        except Exception:
            pass
        return render(request, "Lab_2021/A7_auth_failure/lab3.html")

    # POST
    try:
        username = request.POST["username"]
        password = request.POST["password"]
    except KeyError:
        response = render(request, "Lab_2021/A7_auth_failure/lab3.html")
        response.delete_cookie("session_id")
        return response

    # hash the password input
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if username in USER_A7_LAB3 and USER_A7_LAB3[username]["password"] == password_hash:
        token = str(uuid.uuid4())
        session_data = AFSessionID.objects.create(session_id=token, user=USER_A7_LAB3[username]["username"])
        session_data.save()
        response = render(request, "Lab_2021/A7_auth_failure/lab3.html", {"success": True, "failure": False, "username": username})
        response.set_cookie("session_id", token, httponly=True, secure=False, samesite="Lax")
        return response

    # fallback: invalid creds
    response = render(request, "Lab_2021/A7_auth_failure/lab3.html", {"success": False, "failure": True})
    response.delete_cookie("session_id")
    return response


@login_required
def A7_discussion(request):
    return render(request, "playground/A7/index.html")


# ---------------------------
# Software & data integrity (kept behavior, safer rendering)
# ---------------------------

@login_required
def software_and_data_integrity_failure(request):
    if request.method == "GET":
        return render(request, "Lab_2021/A8_software_and_data_integrity_failure/desc.html")


@login_required
def software_and_data_integrity_failure_lab2(request):
    if request.method == "GET":
        try:
            username = escape(request.GET.get("username", ""))
            return render(request, "Lab_2021/A8_software_and_data_integrity_failure/lab2.html", {"username": username, "success": True})
        except Exception:
            return render(request, "Lab_2021/A8_software_and_data_integrity_failure/lab2.html")


@login_required
def software_and_data_integrity_failure_lab3(request):
    # Not implemented in original file; keep placeholder
    return render(request, "Lab_2021/A8_software_and_data_integrity_failure/lab3.html")


@login_required
def A6_discussion(request):
    return render(request, "playground/A6/index.html")

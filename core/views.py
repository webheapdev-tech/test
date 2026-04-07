import base64
import hashlib
import os
import pickle
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
from datetime import datetime

from django.conf import settings
from django.db import connection
from django.db.utils import IntegrityError
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template import Context, Template
from django.views.decorators.csrf import csrf_exempt

from .models import GuestbookEntry, LabUser, SecretRecord, UploadedDocument


def index(request):
    return render(request, "core/index.html")


def seed_data(request):
    # VULN: unauthenticated endpoint that creates test users and secrets.
    admin_user, _ = LabUser.objects.get_or_create(
        username="admin",
        defaults={
            "password": "admin123",
            "role": "admin",
            "api_token": "SUPER-SECRET-ADMIN-TOKEN",
        },
    )
    alice, _ = LabUser.objects.get_or_create(
        username="alice",
        defaults={"password": "password", "role": "user", "api_token": "alice-token"},
    )
    bob, _ = LabUser.objects.get_or_create(
        username="bob",
        defaults={"password": "123456", "role": "user", "api_token": "bob-token"},
    )

    SecretRecord.objects.get_or_create(
        owner=admin_user,
        title="Prod DB Password",
        defaults={"body": "prod-db-password=SuperSecret!"},
    )
    SecretRecord.objects.get_or_create(
        owner=alice,
        title="Alice private note",
        defaults={"body": "alice secret value: 42"},
    )
    SecretRecord.objects.get_or_create(
        owner=bob,
        title="Bob API key",
        defaults={"body": "bob-key=xyz-unsafe"},
    )

    return JsonResponse({"status": "ok", "message": "Seed data ready."})


def login_unsafe(request):
    if request.method != "POST":
        return JsonResponse(
            {"hint": "POST username/password. Vulnerable to SQL injection."}
        )

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    query = (
        "SELECT id, username, role FROM core_labuser "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            row = cursor.fetchone()
    except Exception as exc:
        return JsonResponse({"error": str(exc), "query": query}, status=500)

    if not row:
        return JsonResponse({"login": False, "query": query}, status=401)

    request.session["lab_user_id"] = row[0]
    request.session["lab_username"] = row[1]
    request.session["lab_role"] = row[2]
    return JsonResponse({"login": True, "id": row[0], "username": row[1], "role": row[2]})


def profile_insecure(request):
    # VULN: IDOR by trusting user-controlled user_id.
    user_id = request.GET.get("user_id", request.session.get("lab_user_id", 1))
    user = get_object_or_404(LabUser, id=user_id)
    return JsonResponse(
        {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "api_token": user.api_token,
            "password": user.password,
        }
    )


def record_insecure(request, record_id):
    # VULN: no authorization check on object access.
    record = get_object_or_404(SecretRecord, id=record_id)
    return JsonResponse(
        {
            "id": record.id,
            "owner": record.owner.username,
            "title": record.title,
            "body": record.body,
        }
    )


def reflected_xss(request):
    payload = request.GET.get("q", "guest")
    # VULN: unsanitized reflected HTML.
    return HttpResponse(f"<h1>Hello {payload}</h1><p>Reflected XSS endpoint.</p>")


@csrf_exempt
def guestbook(request):
    if request.method == "POST":
        GuestbookEntry.objects.create(
            name=request.POST.get("name", "anonymous"),
            message=request.POST.get("message", ""),
        )
        return redirect("/guestbook/")

    entries = GuestbookEntry.objects.order_by("-created_at")[:50]
    return render(request, "core/guestbook.html", {"entries": entries})


def command_exec(request):
    # VULN: direct command execution with shell=True.
    cmd = request.GET.get("cmd", "id")
    try:
        output = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=8,
        )
    except Exception as exc:
        output = str(exc)
    return HttpResponse(f"<pre>{output}</pre>")


def file_read(request):
    # VULN: path traversal/local file read.
    path = request.GET.get("path", "manage.py")
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            content = handle.read()
    except Exception as exc:
        content = str(exc)
    return HttpResponse(f"<h3>{path}</h3><pre>{content}</pre>")


@csrf_exempt
def pickle_deserialize(request):
    # VULN: insecure deserialization.
    payload = request.POST.get("payload", request.GET.get("payload", ""))
    if not payload:
        return JsonResponse({"hint": "Send base64-encoded pickle in payload."})

    try:
        decoded = base64.b64decode(payload)
        obj = pickle.loads(decoded)
        return JsonResponse({"result": str(obj), "type": str(type(obj))})
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=500)


def open_redirect(request):
    # VULN: unvalidated redirect target.
    target = request.GET.get("next", "/")
    return redirect(target)


def ssrf_fetch(request):
    # VULN: server-side request forgery.
    url = request.GET.get("url", "http://127.0.0.1:8000/debug-env/")
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            body = response.read(2500).decode("utf-8", errors="ignore")
            status_code = response.status
    except urllib.error.URLError as exc:
        return JsonResponse({"error": str(exc), "url": url}, status=500)

    return JsonResponse({"url": url, "status": status_code, "body_preview": body})


@csrf_exempt
def upload_unsafe(request):
    if request.method != "POST":
        docs = list(
            UploadedDocument.objects.order_by("-uploaded_at").values(
                "id", "filename", "file", "uploaded_at"
            )[:20]
        )
        return JsonResponse(
            {
                "hint": "POST multipart form-data with file=<anything>.",
                "files": docs,
            }
        )

    uploaded_file = request.FILES.get("file")
    if not uploaded_file:
        return JsonResponse({"error": "missing file"}, status=400)

    doc = UploadedDocument.objects.create(
        filename=uploaded_file.name,
        file=uploaded_file,
    )
    return JsonResponse(
        {
            "stored_as": doc.file.name,
            "url": doc.file.url,
        }
    )


@csrf_exempt
def change_password_get(request):
    # VULN: state-changing action over GET without auth/CSRF.
    user_id = request.GET.get("user_id")
    new_password = request.GET.get("new_password", "newpass123")
    if not user_id:
        return JsonResponse({"error": "user_id is required"}, status=400)

    user = get_object_or_404(LabUser, id=user_id)
    user.password = new_password
    user.save(update_fields=["password"])
    return JsonResponse({"status": "changed", "user": user.username, "password": user.password})


def template_injection(request):
    # VULN: user-controlled template rendering.
    tpl = request.GET.get("tpl", "Hello {{ request.META.HTTP_HOST }}")
    try:
        rendered = Template(tpl).render(Context({"request": request, "os": os}))
        return render(request, "core/template_injection.html", {"rendered": rendered})
    except Exception as exc:
        return render(request, "core/template_injection.html", {"rendered": f"Template error: {exc}"}, status=500)


def debug_env(request):
    # VULN: sensitive information exposure.
    return JsonResponse(dict(os.environ))


@csrf_exempt
def register_mass_assignment(request):
    # VULN: attacker can set privileged fields directly.
    if request.method != "POST":
        return JsonResponse(
            {
                "hint": (
                    "POST username/password/role/api_token. "
                    "No validation, no auth, no CSRF."
                )
            }
        )

    try:
        user = LabUser.objects.create(
            username=request.POST.get("username", f"user{LabUser.objects.count() + 1}"),
            password=request.POST.get("password", "123456"),
            role=request.POST.get("role", "user"),
            api_token=request.POST.get("api_token", "generated-token"),
        )
    except IntegrityError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    return JsonResponse(
        {
            "created": True,
            "id": user.id,
            "username": user.username,
            "password": user.password,
            "role": user.role,
            "api_token": user.api_token,
        }
    )


def impersonate_user(request):
    # VULN: authentication bypass via direct user-id impersonation.
    user_id = request.GET.get("user_id", "1")
    user = get_object_or_404(LabUser, id=user_id)
    request.session["lab_user_id"] = user.id
    request.session["lab_username"] = user.username
    request.session["lab_role"] = user.role
    return JsonResponse(
        {
            "impersonated": True,
            "id": user.id,
            "username": user.username,
            "role": user.role,
        }
    )


def admin_panel_weak(request):
    # VULN: trusts user-controlled query param for admin access.
    if request.GET.get("admin") == "1" or request.session.get("lab_role") == "admin":
        users = list(
            LabUser.objects.values("id", "username", "password", "role", "api_token")
        )
        return JsonResponse({"admin": True, "users": users})
    return JsonResponse({"admin": False, "hint": "Try ?admin=1"}, status=403)


def eval_exec(request):
    # VULN: arbitrary python execution with eval.
    expr = request.GET.get("expr", "__import__('os').popen('id').read()")
    try:
        result = eval(expr)
    except Exception as exc:
        result = str(exc)
    return HttpResponse(f"<pre>{result}</pre>")


def user_search_sqli(request):
    # VULN: SQL injection in search query.
    term = request.GET.get("q", "")
    query = (
        "SELECT id, username, password, role, api_token FROM core_labuser "
        f"WHERE username LIKE '%{term}%'"
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()
    except Exception as exc:
        return JsonResponse({"error": str(exc), "query": query}, status=500)

    data = []
    for row in rows:
        data.append(
            {
                "id": row[0],
                "username": row[1],
                "password": row[2],
                "role": row[3],
                "api_token": row[4],
            }
        )
    return JsonResponse({"query": query, "results": data})


@csrf_exempt
def reset_password_predictable(request):
    # VULN: predictable reset token + no ownership checks.
    user_id = request.GET.get("user_id", request.POST.get("user_id", "1"))
    user = get_object_or_404(LabUser, id=user_id)
    date_fragment = datetime.utcnow().strftime("%Y%m%d")
    token = hashlib.md5(f"{user.id}:{date_fragment}".encode()).hexdigest()[:12]

    provided_token = request.GET.get("token", request.POST.get("token"))
    if not provided_token:
        return JsonResponse(
            {
                "user_id": user.id,
                "predictable_token": token,
                "hint": "Send token + new_password to reset instantly.",
            }
        )

    if provided_token != token:
        return JsonResponse({"error": "invalid token"}, status=403)

    new_password = request.GET.get(
        "new_password", request.POST.get("new_password", "reset123")
    )
    user.password = new_password
    user.save(update_fields=["password"])
    return JsonResponse({"status": "changed", "username": user.username, "password": user.password})


@csrf_exempt
def extract_tar_unsafe(request):
    # VULN: extraction without path validation (Zip Slip style).
    if request.method != "POST":
        return JsonResponse({"hint": "POST multipart with file=<tar archive>."})

    archive = request.FILES.get("file")
    if not archive:
        return JsonResponse({"error": "missing file"}, status=400)

    tmp_dir = tempfile.mkdtemp(prefix="vulnlab_tar_")
    archive_path = os.path.join(tmp_dir, archive.name)
    with open(archive_path, "wb+") as dst:
        for chunk in archive.chunks():
            dst.write(chunk)

    destination = os.path.join(settings.MEDIA_ROOT, "extracted")
    os.makedirs(destination, exist_ok=True)
    with tarfile.open(archive_path) as tar:
        members = tar.getnames()
        tar.extractall(path=destination)

    return JsonResponse({"destination": destination, "members": members[:40]})


def users_leak_cors(request):
    # VULN: sensitive data exposure + permissive CORS.
    users = list(LabUser.objects.values("id", "username", "password", "role", "api_token"))
    response = JsonResponse({"users": users})
    response["Access-Control-Allow-Origin"] = "*"
    response["Access-Control-Allow-Credentials"] = "true"
    return response

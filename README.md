# VulnLab Django (Intentionally Vulnerable)

Aplicatie Django construita intentionat cu vulnerabilitati pentru testarea scannerelor de securitate.

Nu folosi aceasta aplicatie in productie si nu o expune public.

## Rulare

```bash
python3 manage.py migrate
python3 manage.py runserver
```

Deschide:
- `http://127.0.0.1:8000/`
- apoi `http://127.0.0.1:8000/seed/` pentru date demo

## Utilizatori demo

Sunt create de endpoint-ul `/seed/`:
- `admin / admin123`
- `alice / password`
- `bob / 123456`

## Vulnerabilitati incluse

- SQL Injection (`/login-unsafe/`)
- SQL Injection (search) (`/users-search/`)
- Plaintext passwords (`LabUser.password`)
- Mass Assignment / Privilege Escalation (`/register-mass/`)
- Session Impersonation / Auth Bypass (`/impersonate/`)
- Admin Bypass via Query Param (`/admin-panel/?admin=1`)
- IDOR / Broken Access Control (`/profile/`, `/records/<id>/`)
- CORS Misconfiguration + Sensitive Data Leak (`/users-leak/`)
- Reflected XSS (`/xss-reflected/`)
- Stored XSS + CSRF disabled (`/guestbook/`)
- Command Injection / RCE (`/cmd/`)
- Arbitrary Python Eval RCE (`/eval/`)
- Path Traversal / Local File Read (`/read-file/`)
- Insecure Deserialization (`/pickle/`)
- Predictable Password Reset Token (`/reset-password/`)
- Open Redirect (`/go/`)
- SSRF (`/fetch/`)
- Unrestricted File Upload (`/upload/`)
- Unsafe TAR Extraction / Zip Slip style (`/extract-tar/`)
- Sensitive info exposure (`/debug-env/`)
- State-changing GET without auth/CSRF (`/change-password/`)
- Template Injection (`/ssti/`)
- Insecure Django settings (`ALLOWED_HOSTS=*`, weak `SECRET_KEY`, weak password hashing, insecure cookies)

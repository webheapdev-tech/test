from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("seed/", views.seed_data, name="seed_data"),
    path("login-unsafe/", views.login_unsafe, name="login_unsafe"),
    path("register-mass/", views.register_mass_assignment, name="register_mass"),
    path("impersonate/", views.impersonate_user, name="impersonate_user"),
    path("admin-panel/", views.admin_panel_weak, name="admin_panel_weak"),
    path("profile/", views.profile_insecure, name="profile_insecure"),
    path("records/<int:record_id>/", views.record_insecure, name="record_insecure"),
    path("users-search/", views.user_search_sqli, name="user_search_sqli"),
    path("users-leak/", views.users_leak_cors, name="users_leak_cors"),
    path("xss-reflected/", views.reflected_xss, name="reflected_xss"),
    path("guestbook/", views.guestbook, name="guestbook"),
    path("cmd/", views.command_exec, name="command_exec"),
    path("eval/", views.eval_exec, name="eval_exec"),
    path("read-file/", views.file_read, name="file_read"),
    path("pickle/", views.pickle_deserialize, name="pickle_deserialize"),
    path("reset-password/", views.reset_password_predictable, name="reset_password"),
    path("go/", views.open_redirect, name="open_redirect"),
    path("fetch/", views.ssrf_fetch, name="ssrf_fetch"),
    path("upload/", views.upload_unsafe, name="upload_unsafe"),
    path("extract-tar/", views.extract_tar_unsafe, name="extract_tar_unsafe"),
    path("change-password/", views.change_password_get, name="change_password_get"),
    path("ssti/", views.template_injection, name="template_injection"),
    path("debug-env/", views.debug_env, name="debug_env"),
]

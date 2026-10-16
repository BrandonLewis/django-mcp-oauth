"""Minimal Django settings for django-mcp-oauth's own test suite."""

import os
from pathlib import Path

# Authlib refuses http:// redirect/request URIs unless told the transport is
# insecure on purpose; the Django test client is http://testserver.
os.environ.setdefault("AUTHLIB_INSECURE_TRANSPORT", "1")

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = "test-only"
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django_mcp_oauth",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "tests.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
USE_TZ = True
LOGIN_URL = "/accounts/login/"

# The two required settings; tests override the rest per case.
MCP_OAUTH_ISSUER = "http://testserver"
MCP_RESOURCE_URL = "http://testserver/mcp"
MCP_OAUTH_ACCESS_TOKEN_TTL = 900

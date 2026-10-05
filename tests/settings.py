"""Settings for the package's own test suite: a minimal project using the preset."""

from titan_mcp_auth.conf import oauth2_settings

SECRET_KEY = "titan-mcp-auth-tests-only"
DEBUG = False
ALLOWED_HOSTS = ["testserver"]
USE_TZ = True
ROOT_URLCONF = "tests.urls"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "titan_mcp_auth",
    "oauth2_provider",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csp.ContentSecurityPolicyMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": ["django.template.context_processors.request"]},
    }
]
SECURE_CSP = {"default-src": ["'self'"], "form-action": ["'self'"]}
LOGIN_URL = "/login/"
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

OAUTH2_PROVIDER = oauth2_settings(resource_name="Test", scope_description="Use the test tools")
TITAN_MCP = {"CAN_CONNECT": "titan_mcp_auth.policy.superuser_only"}

"""The contract suite under the package default, active_user."""

import pytest

from mcp_auth.testing import MCPAuthContract


class TestContractActiveUser(MCPAuthContract):
    """Every Claude connector requirement, when any active account may connect."""

    mcp_path = "/mcp"

    @pytest.fixture(autouse=True)
    def _active_user_rule(self, settings):
        settings.MCP_AUTH = {"CAN_CONNECT": "mcp_auth.policy.active_user"}

    def make_allowed_user(self, django_user_model):
        return django_user_model.objects.create_user("member", password="pw")

    def make_refused_user(self, django_user_model):
        return django_user_model.objects.create_user("gone", password="pw", is_active=False)


class TestContractActiveUserAllowAllBackend(TestContractActiveUser):
    """The same, with a backend that keeps inactive accounts signed in."""

    @pytest.fixture(autouse=True)
    def _allow_inactive_sessions(self, settings):
        settings.AUTHENTICATION_BACKENDS = [
            "django.contrib.auth.backends.AllowAllUsersModelBackend"
        ]

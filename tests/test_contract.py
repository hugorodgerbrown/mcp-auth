"""The contract suite, run against the test project (superuser-only rule)."""

from mcp_auth.testing import MCPAuthContract


class TestContract(MCPAuthContract):
    """Every Claude connector requirement, against tests/urls.py."""

    mcp_path = "/mcp"

    def make_allowed_user(self, django_user_model):
        return django_user_model.objects.create_superuser("owner", password="pw")

    def make_refused_user(self, django_user_model):
        return django_user_model.objects.create_user("guest", password="pw")

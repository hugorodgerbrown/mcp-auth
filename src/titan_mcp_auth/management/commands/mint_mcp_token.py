"""mint_mcp_token: issue an access token for local testing with curl.

    TOKEN=$(python manage.py mint_mcp_token --commit -v 0)
    curl -X POST http://localhost:8000/mcp -H "Authorization: Bearer $TOKEN" ...

Read-only without --commit: it says what it would mint and for whom. The
token belongs to a "Local token (mint_mcp_token)" client, so it shows on the
connected-apps page and Disconnect revokes it.
"""

import datetime as dt
import secrets
from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.utils import timezone
from oauth2_provider.models import get_access_token_model, get_application_model, set_token_value

from ...conf import titan_setting
from ...policy import can_connect

CLIENT_NAME = "Local token (mint_mcp_token)"
DEFAULT_RESOURCE = "http://localhost:8000/mcp"


class Command(BaseCommand):
    """Mint one MCP access token, printed once."""

    help = "Mint an MCP access token for local testing (read-only without --commit)."

    def add_arguments(self, parser: CommandParser) -> None:
        """--username, --resource, --hours and --commit."""
        parser.add_argument(
            "--username", help="Whose token. Defaults to the only superuser, if there is one."
        )
        parser.add_argument(
            "--resource", default=DEFAULT_RESOURCE, help=f"The MCP URL (default {DEFAULT_RESOURCE})"
        )
        parser.add_argument("--hours", type=int, default=1, help="Lifetime in hours (default 1)")
        parser.add_argument("--commit", action="store_true", help="Mint it. Otherwise dry run.")

    def handle(self, *args: Any, **options: Any) -> None:
        """Find the user, check the connect rule, and mint the token."""
        user = self._user(options["username"])
        if not can_connect(user):
            raise CommandError(f"{user} may not connect under TITAN_MCP['CAN_CONNECT'].")
        if not options["commit"]:
            self.stderr.write(
                f"Would mint a {options['hours']} h token for {user} on {options['resource']}. "
                "Pass --commit to mint it."
            )
            return

        application, _ = get_application_model().objects.get_or_create(
            name=CLIENT_NAME,
            user=user,
            defaults={
                "client_type": "public",
                "authorization_grant_type": "authorization-code",
                "redirect_uris": "http://127.0.0.1/",
            },
        )
        raw = secrets.token_urlsafe(32)
        token = get_access_token_model()(
            user=user,
            application=application,
            scope=titan_setting("SCOPE"),
            resource=[options["resource"]],
            expires=timezone.now() + dt.timedelta(hours=options["hours"]),
        )
        set_token_value(token, raw)
        token.save()
        if options["verbosity"] > 0:
            self.stderr.write(f"Minted a token for {user}, expiring in {options['hours']} h:")
        self.stdout.write(raw)

    def _user(self, username: str | None) -> Any:
        """The named user, or the only superuser."""
        users = get_user_model().objects.all()
        if username:
            try:
                return users.get(username=username)
            except users.model.DoesNotExist:
                raise CommandError(f"No user {username!r}.") from None
        supers = list(users.filter(is_superuser=True)[:2])
        if len(supers) != 1:
            raise CommandError("Name the user with --username.")
        return supers[0]

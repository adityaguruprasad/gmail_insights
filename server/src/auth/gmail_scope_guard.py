"""Server-side Gmail OAuth scope validation."""

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"
GMAIL_READONLY_SCOPE = "gmail.readonly"

_GOOGLE_AUTH_PREFIX = "https://www.googleapis.com/auth/"
_FULL_MAIL_SCOPE = "https://mail.google.com/"
_FULL_MAIL_SCOPE_NAME = "mail.google.com"
_ALLOWED_GMAIL_SCOPES = frozenset({GMAIL_READONLY_SCOPE})


class TokenScopeValidationError(ValueError):
    """Raised when a bearer token's Gmail scopes are missing or overbroad."""


def _canonical_scope_name(scope: str) -> str:
    scope = scope.strip()
    if (
        scope.rstrip("/") == _FULL_MAIL_SCOPE.rstrip("/")
        or scope == _FULL_MAIL_SCOPE_NAME
        or scope.startswith(_FULL_MAIL_SCOPE)
        or scope.startswith(f"{_FULL_MAIL_SCOPE_NAME}/")
    ):
        return _FULL_MAIL_SCOPE_NAME
    if scope.startswith(_GOOGLE_AUTH_PREFIX):
        return scope[len(_GOOGLE_AUTH_PREFIX) :]
    return scope


def _parse_scope_string(scope_value: str) -> set[str]:
    return {
        _canonical_scope_name(scope)
        for scope in scope_value.split()
        if scope and scope.strip()
    }


def fetch_tokeninfo(token: str) -> dict:
    """Fetch token metadata from Google's tokeninfo API."""

    data = urlencode({"access_token": token}).encode("ascii")
    request = Request(
        TOKENINFO_URL,
        data=data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    with urlopen(request, timeout=5) as response:
        body = response.read(65536)

    tokeninfo = json.loads(body.decode("utf-8"))
    if not isinstance(tokeninfo, dict):
        raise TokenScopeValidationError("Token metadata could not be verified")
    return tokeninfo


def _extract_tokeninfo_scopes(tokeninfo: dict) -> set[str]:
    scope_value = tokeninfo.get("scope")
    if not isinstance(scope_value, str):
        raise TokenScopeValidationError("Token scope could not be verified")

    scopes = _parse_scope_string(scope_value)
    if not scopes:
        raise TokenScopeValidationError("Token scope could not be verified")
    return scopes


def fetch_token_scopes(token: str) -> set[str]:
    """Fetch OAuth scopes granted to an access token from Google's tokeninfo API."""

    return _extract_tokeninfo_scopes(fetch_tokeninfo(token))


def _validate_token_audience(tokeninfo: dict, expected_audience: str) -> None:
    if not isinstance(expected_audience, str) or not expected_audience.strip():
        raise TokenScopeValidationError("Token audience could not be verified")

    audience = tokeninfo.get("aud")
    if not isinstance(audience, str) or audience != expected_audience.strip():
        raise TokenScopeValidationError("Token audience could not be verified")


def _canonicalize_scopes(scopes) -> set[str]:
    canonical_scopes = set()
    for scope in scopes:
        if not isinstance(scope, str) or not scope.strip():
            raise TokenScopeValidationError("Token scope could not be verified")
        canonical_scopes.add(_canonical_scope_name(scope))
    if not canonical_scopes:
        raise TokenScopeValidationError("Token scope could not be verified")
    return canonical_scopes


def _is_gmail_scope(canonical_scope: str) -> bool:
    return canonical_scope.startswith("gmail.") or canonical_scope.startswith(
        _FULL_MAIL_SCOPE_NAME
    )


def validate_gmail_readonly_token(
    token: str,
    expected_audience: str,
    tokeninfo_fetcher=fetch_tokeninfo,
    scope_fetcher=None,
) -> set[str]:
    """Require gmail.readonly and reject every other Gmail OAuth scope."""

    if not isinstance(token, str) or not token.strip():
        raise TokenScopeValidationError("Token scope could not be verified")

    try:
        tokeninfo = tokeninfo_fetcher(token)
        if not isinstance(tokeninfo, dict):
            raise TokenScopeValidationError("Token metadata could not be verified")
        _validate_token_audience(tokeninfo, expected_audience)
        scopes = (
            scope_fetcher(token)
            if scope_fetcher is not None
            else _extract_tokeninfo_scopes(tokeninfo)
        )
    except (
        HTTPError,
        URLError,
        TimeoutError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise TokenScopeValidationError("Token scope could not be verified") from exc

    try:
        canonical_scopes = _canonicalize_scopes(scopes)
    except (TypeError, ValueError) as exc:
        raise TokenScopeValidationError("Token scope could not be verified") from exc

    if GMAIL_READONLY_SCOPE not in canonical_scopes:
        raise TokenScopeValidationError("Token is missing required Gmail scope")
    if any(
        _is_gmail_scope(scope) and scope not in _ALLOWED_GMAIL_SCOPES
        for scope in canonical_scopes
    ):
        raise TokenScopeValidationError("Token has overbroad Gmail scope")

    return canonical_scopes

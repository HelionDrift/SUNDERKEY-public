"""Ephemeral provider credential resolution for provider workers.

Credential references cross the execution boundary. Credential values do not.
The resolver returns a short-lived lease whose representation is always redacted
and whose value is cleared when the context closes.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from typing import Protocol, runtime_checkable

OPENAI_ENVIRONMENT_CREDENTIAL_REFERENCE = "ref:env:OPENAI_API_KEY"
_REFERENCE = re.compile(r"ref:[A-Za-z0-9][A-Za-z0-9._:/-]{2,251}\Z")


class ProviderCredentialResolutionError(ValueError):
    """Raised when an opaque credential reference cannot be resolved safely."""


class ProviderCredentialLease:
    """Process-local, short-lived access to one provider credential."""

    __slots__ = ("_active", "_secret")

    def __init__(self, secret: str) -> None:
        if (
            not isinstance(secret, str)
            or not secret
            or len(secret) > 4096
            or secret != secret.strip()
            or any(character.isspace() for character in secret)
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in secret)
        ):
            raise ProviderCredentialResolutionError("Provider credential is unavailable or invalid")
        self._secret: str | None = secret
        self._active = True

    def __repr__(self) -> str:
        return "ProviderCredentialLease(active=<redacted>)"

    def bearer_authorization(self) -> str:
        """Return the authorization value only while the worker lease is active."""

        if not self._active or self._secret is None:
            raise ProviderCredentialResolutionError("Provider credential lease is closed")
        return f"Bearer {self._secret}"

    def close(self) -> None:
        self._secret = None
        self._active = False

    def __enter__(self) -> ProviderCredentialLease:
        if not self._active:
            raise ProviderCredentialResolutionError("Provider credential lease is closed")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


@runtime_checkable
class ProviderCredentialResolver(Protocol):
    """Resolve an opaque reference only inside a provider worker call."""

    def open_credential(
        self,
        credential_reference: str,
    ) -> AbstractContextManager[ProviderCredentialLease]: ...


class EnvironmentProviderCredentialResolver:
    """Resolve the one approved OpenAI environment reference on demand."""

    def __init__(
        self,
        *,
        environment_lookup: Callable[[str], str | None] | None = None,
        approved_reference: str = OPENAI_ENVIRONMENT_CREDENTIAL_REFERENCE,
    ) -> None:
        if (
            not isinstance(approved_reference, str)
            or _REFERENCE.fullmatch(approved_reference) is None
        ):
            raise ProviderCredentialResolutionError("Approved credential reference is invalid")
        self._environment_lookup = environment_lookup or os.environ.get
        self._approved_reference = approved_reference

    def __repr__(self) -> str:
        return "EnvironmentProviderCredentialResolver(reference_policy=approved_only)"

    @contextmanager
    def open_credential(
        self,
        credential_reference: str,
    ) -> Iterator[ProviderCredentialLease]:
        if (
            not isinstance(credential_reference, str)
            or _REFERENCE.fullmatch(credential_reference) is None
            or credential_reference != self._approved_reference
        ):
            raise ProviderCredentialResolutionError("Provider credential reference is not approved")
        try:
            value = self._environment_lookup("OPENAI_API_KEY")
        except Exception:
            raise ProviderCredentialResolutionError(
                "Provider credential lookup did not complete"
            ) from None
        lease = ProviderCredentialLease(value)  # type: ignore[arg-type]
        try:
            yield lease
        finally:
            lease.close()
__all__ = [
    "EnvironmentProviderCredentialResolver",
    "OPENAI_ENVIRONMENT_CREDENTIAL_REFERENCE",
    "ProviderCredentialLease",
    "ProviderCredentialResolutionError",
    "ProviderCredentialResolver",
]

#!/usr/bin/env python3
# Copyright(C) 2023 Maya Costantini
# sigstore-key-signer
#
# This program is free software: you can redistribute it and / or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

"""
Vault adapter for storing and retrieving keys.
Provides shortcuts for `store`, `retrieve` and `delete` operations
and a `hvac.Client` attribute stored as `Vault.client` for more flexibility.
"""

import hvac
import logging
import os

from sigstore_key_signer.adapters.base import BaseAdapter
from typing import Any, Optional


logger = logging.getLogger(__name__)


VAULT_ENV = {
    "VAULT_TOKEN",
    "VAULT_ADDR",
    "VAULT_CACERT",
    "VAULT_CAPATH",
    "VAULT_CLIENT_CERT",
    "VAULT_CLIENT_KEY",
    "VAULT_CLIENT_TIMEOUT",
    "VAULT_FORMAT",
    "VAULT_MAX_RETRIES",
    "VAULT_SKIP_VERIFY",
    "VAULT_TLS_SERVER_NAME",
    "VAULT_RATE_LIMIT",
    "VAULT_HTTP_PROXY",
    "VAULT_PROXY_ADDR",
    "VAULT_DISABLE_REDIRECTS",
}


_AUTH_METHODS = (
    "tls",
    "tls_client_side_cert",
    "http",
)


class Vault(BaseAdapter):
    """Vault adapter for storing and retrieving keys."""

    def __init__(self, auth_method: str) -> None:
        """Initialize a `Vault` client and warn for missing environment variables."""
        missing_vars = set(VAULT_ENV).difference(os.environ.keys())
        if missing_vars:
            logger.warn(
                f"Vault environment variables missing: {missing_vars}\n"
                "Could not initialize corresponding attributes."
            )

        if auth_method not in _AUTH_METHODS:
            raise ValueError(
                f"Unknow authentication method {auth_method}. Valid values are: {_AUTH_METHODS}"
            )
        self.auth_method = auth_method

        if self.auth_method == "tls":
            self.client = hvac.Client(
                url=self.url,
            )

        elif auth_method == "tls_client_side_cert":
            self.client = hvac.Client(
                url=self.url,
                token=self.token,
                cert=(self.client_cert, self.client_key),
                verify=self.ca_path,
            )

        elif auth_method == "http":
            logger.warn("Insecure Vault authentication method: `http`")
            self.client = hvac.Client(
                url=self.url,
            )

    @staticmethod
    def check_scheme(url: str, expected: str) -> None:
        """Check that the URL scheme is the one expected."""
        scheme = url.split("://")[0]
        if scheme != expected:
            raise ValueError(
                f"Incorrect scheme specified for Vault URL: {scheme}: expected `https`"
            )
        return

    def _get_or_set_from_env(self, attr: str, env: str) -> Any:
        """Get or set an attribute from the environment."""
        if not hasattr(self, attr):
            try:
                setattr(self, attr, os.environ[env])
            except KeyError:
                raise
        return getattr(self, attr)

    def store(
        self,
        path: str,
        secret: dict,
        cas: Optional[int],
        mount_point: str = "secret",
    ) -> bool:
        """Store or uptade a signing key on the server."""
        return self.client.secrets.kv.v2.create_or_update_secret(
            path=path,
            cas=cas,
            secret=secret,
            mount_point=mount_point,
        )

    def retrieve(
        self,
        path: str,
        version: Optional[int],
        raise_on_deleted_version: Optional[bool],
        mount_point: Optional[str] = "secret",
    ) -> str:
        """Retrieve the signing key at the specified location, with the specified version."""
        resp = self.client.secrets.kv.read_secret_version(
            path=path,
            version=version,
            raise_on_deleted_version=raise_on_deleted_version,
            mount_point=mount_point,
        )

        return resp["data"]["data"]["password"]

    def delete(
        self,
        path: str,
        versions: int,
        mount_point: Optional[str] = "secret",
    ) -> bool:
        """Delete a stored signing key."""
        return self.client.secrets.kv.v2.delete_secret_versions(
            path=path,
            versions=versions,
            mount_point=mount_point,
        )

    @property
    def token(self) -> str:
        """Authentication token for the Vault client."""
        return self._get_or_set_from_env("token", "VAULT_TOKEN")

    @property
    def url(self) -> str:
        """Vault server URL."""
        return self._get_or_set_from_env("url", "VAULT_ADDR")

    @property
    def ca_cert(self) -> str:
        """Path to a CA certificate file on the local disk."""
        return self._get_or_set_from_env("ca_cert", "VAULT_CACERT")

    @property
    def ca_path(self) -> str:
        """Path to a directory of CA certificate files on the local disk"""
        return self._get_or_set_from_env("ca_path", "VAULT_CAPATH")

    @property
    def client_cert(self) -> str:
        """Path to a client certificate on the local disk"""
        return self._get_or_set_from_env("client_cert", "VAULT_CLIENT_CERT")

    @property
    def client_key(self) -> str:
        """Path to an unencrypted private key on disk which corresponds to the matching client certificate."""
        return self._get_or_set_from_env("client_key", "VAULT_CLIENT_KEY")

    @property
    def client_timeout(self) -> int:
        """Timeout variable."""
        return self._get_or_set_from_env("client_timeout", "VAULT_CLIENT_TIMEOUT")

    @property
    def format(self) -> str:
        """Provide Vault output (read/status/write) in the specified format."""
        return self._get_or_set_from_env("format", "VAULT_FORMAT")

    @property
    def max_retries(self) -> str:
        """Maximum number of retries when certain error codes are encountered."""
        return self._get_or_set_from_env("max_retries", "VAULT_MAX_RETRIES")

    @property
    def skip_verify(self) -> str:
        """Do not verify Vault's presented certificate before communicating with it (not recommended)."""
        return self._get_or_set_from_env("skip_verify", "VAULT_SKIP_VERIFY")

    @property
    def tls_server_name(self) -> str:
        """Name to use as the SNI host when connecting via TLS."""
        return self._get_or_set_from_env("tls_server_name", "VAULT_TLS_SERVER_NAME")

    @property
    def rate_limit(self) -> str:
        """Limit the rate at which the vault command sends requests to Vault."""
        return self._get_or_set_from_env("rate_limit", "VAULT_RATE_LIMIT")

    @property
    def http_proxy(self) -> str:
        """HTTP or HTTPS proxy location which should be used by all requests to access Vault."""
        return self._get_or_set_from_env("http_proxy", "VAULT_HTTP_PROXY")

    @property
    def proxy_addr(self) -> str:
        """HTTP or HTTPS proxy location which should be used by all requests to access Vault."""
        return self._get_or_set_from_env("proxy_addr", "VAULT_PROXY_ADDR")

    @property
    def disable_redirects(self) -> str:
        """Prevents the Vault client from following redirects."""
        return self._get_or_set_from_env("disable_redirects", "VAULT_DISABLE_REDIRECTS")

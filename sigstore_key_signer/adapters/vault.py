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
import re

from requests import Response
from sigstore_key_signer.adapters.base import BaseAdapter
from typing import Any


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


class Vault(BaseAdapter):
    """Vault adapter for storing and retrieving keys."""

    def __init__(self) -> None:
        """Initialize a `Vault` client and warn for missing environment variables."""
        missing_vars = set(VAULT_ENV).difference(os.environ.keys())
        if missing_vars:
            logger.warn(
                f"Vault environment variables missing: {missing_vars}\n"
                "Could not initialize corresponding attributes."
            )

        self.check_scheme()
        self.client = hvac.Client(url=self.uri)

    def check_scheme(self) -> None:
        """Check that the URL scheme is the one expected."""
        if re.match(re.compile(self.uri_scheme), self.uri) is None:
            raise ValueError(
                f"Incorrect scheme specified for Vault URL: {self.uri}: expected expression matching {self.uri_scheme}"
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

    def store(self, key_name: str) -> Response:
        """Store a key on the server at the default path `/transit/keys/{key_name}`"""
        return self.client.secrets.transit.create_key(key_name)

    def retrieve(self, key_name: str) -> dict:
        """Retrieve the public key at the default path `/transit/keys/{key_name}`."""
        resp = self.client.secrets.transit.read_key(key_name)
        # Take the key at the first index
        return resp["data"]["keys"]["1"]["public_key"]

    def delete(self, key_name: str) -> bool:
        """Delete a stored key at the default path `/transit/keys/{key_name}`."""
        return self.client.secrets.transit.delete_key(key_name)

    def sign(
        self,
        key_name: str,
        hash_input: str,
    ) -> bytes:
        """Sign an artifact using the private key stored under `key_name`."""
        # Assuming ecdsa-p256 key type
        resp = self.client.secrets.transit.sign_data(
            key_name,
            hash_input,
            prehashed=True,
        )
        sig = resp["data"]["signature"]

        return sig.split(":")[-1].encode()

    @property
    def uri_scheme(self) -> str:
        """Go-cloud-style URI scheme for the Vault server."""
        return r"^hashivault://(\w(([\w\-.]+)?\w)?)$"

    @property
    def token(self) -> str:
        """Authentication token for the Vault client."""
        return self._get_or_set_from_env("token", "VAULT_TOKEN")

    @property
    def uri(self) -> str:
        """Vault server URI."""
        return self._get_or_set_from_env("uri", "VAULT_ADDR")

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

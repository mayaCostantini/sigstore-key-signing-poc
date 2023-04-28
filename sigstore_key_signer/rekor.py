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
Implementation of a Sigstore Rekor client for self-managed key signing
based on the sigstore-python library.
"""

from __future__ import annotations

import abc
import base64
import json
import logging
import requests

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from sigstore._internal.ctfe import CTKeyring
from sigstore._internal.keyring import Keyring
from sigstore._internal.merkle import (
    InvalidInclusionProofError,
    verify_merkle_inclusion,
)
from sigstore._internal.rekor.client import (
    DEFAULT_REKOR_URL,
    RekorClient,
    RekorClientError,
    RekorEntries,
    RekorEntriesRetrieve,
    RekorKeyring,
    RekorLog,
)
from sigstore._internal.set import InvalidSETError, verify_set
from sigstore._internal.tuf import TrustUpdater
from sigstore._utils import B64Str, HexStr, sha256_streaming
from sigstore.transparency import LogEntry
from sigstore.verify.verifier import LogEntryMissing
from sigstore.verify.models import InvalidRekorEntry as InvalidRekorEntryError
from sigstore.verify.models import RekorEntryMissing as RekorEntryMissingError
from sigstore.verify.models import (
    VerificationFailure,
    VerificationMaterials,
    VerificationResult,
    VerificationSuccess,
)
from typing import cast, IO, Optional, Type, TypeVar
from urllib.parse import urljoin


logger = logging.getLogger(__name__)


class KeyRekorEntriesRetrieve(RekorEntriesRetrieve):
    """
    Override `RekorEntriesRetrieve` to retrieve a log entry containing a public key.
    Original implementation from https://github.com/sigstore/sigstore-python/blob/main/sigstore/_internal/rekor/client.py#L187
    """

    def post(
        self,
        signature: bytes,
        artifact_hash: str,
        public_key: bytes,
    ) -> Optional[LogEntry]:
        """
        This method overrides the original `RekorEntriesRetrieve.post` method from sigstore-python,
        replacing the certificate in the request body with a public key.
        """
        data = {
            "entries": [
                {
                    "kind": "hashedrekord",
                    "apiVersion": "0.0.1",
                    "spec": {
                        "signature": {
                            "content": B64Str(base64.b64encode(signature).decode()),
                            "publicKey": {
                                "content": B64Str(
                                    base64.b64encode(public_key).decode()
                                ),
                            },
                        },
                        "data": {
                            "hash": {
                                "algorithm": "sha256",
                                "value": artifact_hash,
                            }
                        },
                    },
                }
            ]
        }

        resp: requests.Response = self.session.post(self.url, json=data)
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            if http_error.response.status_code == 404:
                return None
            raise RekorClientError(resp.json()) from http_error

        results = resp.json()

        # The response is a list of `{uuid: LogEntry}` objects.
        # We select the oldest entry for our actual return value,
        # since a malicious actor could conceivably spam the log with
        # newer duplicate entries.
        oldest_entry: Optional[LogEntry] = None
        for result in results:
            entry = LogEntry._from_response(result)
            if (
                oldest_entry is None
                or entry.integrated_time < oldest_entry.integrated_time
            ):
                oldest_entry = entry

        return oldest_entry


class KeyRekorEntries(RekorEntries):
    """Override `RekorEntries` to retrieve a log entry containing a public key."""

    @property
    def retrieve(self) -> KeyRekorEntriesRetrieve:
        """
        Returns a `KeyRekorEntriesRetrieve` capable of retrieving entries.
        """
        return KeyRekorEntriesRetrieve(
            urljoin(self.url, "retrieve/"), session=self.session
        )


class KeyRekorLog(RekorLog):
    """Override `RekorLog` to retrieve a log entry containing a public key."""

    @property
    def entries(self) -> KeyRekorEntries:
        """
        Returns a `KeyRekorEntries` capable of accessing detailed information
        about individual log entries.
        """
        return KeyRekorEntries(urljoin(self.url, "entries/"), session=self.session)


class KeyRekorClient(RekorClient):
    """Override `RekorClient` to retrieve a log entry containing a public key."""

    @classmethod
    def production(cls, updater: TrustUpdater) -> KeyRekorClient:
        """
        Returns a `KeyRekorClient` populated with the default Rekor production instance.
        updater must be a `TrustUpdater` for the production TUF repository.
        """
        rekor_keys = updater.get_rekor_keys()
        ctfe_keys = updater.get_ctfe_keys()

        return cls(
            DEFAULT_REKOR_URL,
            RekorKeyring(Keyring(rekor_keys)),
            CTKeyring(Keyring(ctfe_keys)),
        )

    @property
    def log(self) -> KeyRekorLog:
        """
        Returns a `KeyRekorLog` adapter for making requests to a Rekor log.
        """
        return KeyRekorLog(urljoin(self.url, "log/"), session=self.session)

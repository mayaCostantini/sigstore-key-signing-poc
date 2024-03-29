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
Implementation of a Sigstore verifying client for self-managed key signing
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
from sigstore_key_signer.rekor import KeyRekorClient
from typing import cast, IO, Optional, Type, TypeVar
from urllib.parse import urljoin


logger = logging.getLogger(__name__)

T = TypeVar("T", bound="BaseKeyVerifier")


class KeyVerificationMaterials(VerificationMaterials):
    """Representation of verification materials to provide for key-signed artifacts."""

    # Workaround for reusing `VerificationMaterials` from sigstore-python
    certificate = None
    public_key: bytes

    def __init__(
        self,
        input_: IO[bytes],
        signature: bytes,
        public_key: bytes,
        rekor_entry: LogEntry | None,
    ) -> None:
        """Create a new `KeyVerificationMaterials` instance."""
        self.input_digest = sha256_streaming(input_)
        self.public_key = public_key
        self.signature = signature
        self._rekor_entry = rekor_entry
        # TODO: change
        self._offline = False

    def rekor_entry(self, client: KeyRekorClient) -> LogEntry:
        """Returns a `LogEntry` for the current signing materials."""
        entry: LogEntry | None

        if self._offline and self.has_rekor_entry:
            logger.debug("using offline rekor entry")
            entry = self._rekor_entry
        else:
            logger.debug("retrieving rekor entry")

            entry = client.log.entries.retrieve.post(
                self.signature,
                self.input_digest.hex(),
                self.public_key,
            )

        if entry is None:
            raise RekorEntryMissingError

        logger.debug("Rekor entry: ensuring contents match signing materials")

        expected_body = {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "content": B64Str(base64.b64encode(self.signature).decode()),
                    "publicKey": {
                        "content": B64Str(base64.b64encode(self.public_key).decode())
                    },
                },
                "data": {
                    "hash": {"algorithm": "sha256", "value": self.input_digest.hex()}
                },
            },
        }

        actual_body = json.loads(base64.b64decode(entry.body))

        if expected_body != actual_body:
            raise InvalidRekorEntryError

        return entry


class BaseKeyVerifier(abc.ABC):
    """Base class for implementing key verifiers."""

    def __init__(
        self,
        rekor: KeyRekorClient,
    ) -> None:
        """
        Create a new KeyVerifier
        """
        self._rekor = rekor

    @classmethod
    def production(cls: Type[T]) -> T:
        """
        Return a `Verifier` instance configured against Sigstore's production-level services.
        """
        updater = TrustUpdater.production()
        return cls(
            rekor=KeyRekorClient.production(updater),
        )

    @abc.abstractmethod
    def verify(
        self,
        materials: KeyVerificationMaterials,
    ) -> VerificationResult:
        """Verify an artifact signature from the `KeyVerificationMaterials`."""
        raise NotImplementedError


class KeyRefVerifier(BaseKeyVerifier):
    """Verifier instanciated from a path to an existing key."""

    def __init__(self, rekor: KeyRekorClient) -> None:
        """Instanciate a new `KeyRefVerifier`."""
        super().__init__(rekor=rekor)

    def verify(self, materials: KeyVerificationMaterials) -> VerificationResult:
        """Verify a signature given a public key and a Rekor entry."""
        try:
            signing_key = cast(
                ec.EllipticCurvePublicKey,
                serialization.load_pem_public_key(materials.public_key),
            )
            signing_key.verify(
                materials.signature,
                materials.input_digest,
                ec.ECDSA(Prehashed(hashes.SHA256())),
            )
        except InvalidSignature:
            return VerificationFailure(reason="Signature is invalid for input")

        logger.debug("Successfully verified signature...")

        try:
            entry = materials.rekor_entry(self._rekor)

        except RekorEntryMissingError:
            return LogEntryMissing(
                signature=B64Str(base64.b64encode(materials.signature).decode()),
                artifact_hash=HexStr(materials.input_digest.hex()),
            )
        except InvalidRekorEntryError:
            return VerificationFailure(
                reason="Rekor entry contents do not match other signing materials"
            )

        if not materials._offline:
            try:
                verify_merkle_inclusion(entry)
            except InvalidInclusionProofError as exc:
                return VerificationFailure(
                    reason=f"invalid Rekor inclusion proof: {exc}"
                )
        else:
            logger.debug(
                "offline verification requested: skipping Merkle inclusion proof"
            )

        try:
            verify_set(self._rekor, entry)
        except InvalidSETError as inval_set:
            return VerificationFailure(reason=f"invalid Rekor entry SET: {inval_set}")

        logger.debug(f"Successfully verified Rekor entry at index {entry.log_index}")
        return VerificationSuccess()

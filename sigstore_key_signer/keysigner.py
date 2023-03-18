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
Implementation of a Sigstore signing client for self-managed key signing
based on the sigstore-python library.
"""

from __future__ import annotations

import abc
import base64
import getpass
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from pydantic import BaseModel
from sigstore._internal.rekor import RekorClient
from sigstore._internal.tuf import TrustUpdater
from sigstore._utils import B64Str
from sigstore._utils import HexStr
from sigstore._utils import sha256_streaming
from sigstore.transparency import LogEntry
from typing import IO
from typing import Optional
from typing import Type
from typing import TypeVar


logger = logging.getLogger(__name__)

T = TypeVar("T", bound="BaseKeySigner")


class KeySigningResult(BaseModel):
    """Representation of a key-signing result."""

    input_digest: HexStr
    b64_signature: B64Str
    public_key: B64Str
    log_entry: LogEntry


class BaseKeySigner(abc.ABC):
    """Base class for implementing key signers."""

    def __init__(
        self,
        rekor: RekorClient,
    ) -> None:
        """Create a new KeySigner."""
        self._rekor = rekor

    @classmethod
    def production(cls: Type[T]) -> T:
        """
        Return a key signer instance configured against Sigstore's production-level services.
        """
        updater = TrustUpdater.production()
        rekor = RekorClient.production(updater)
        return cls(rekor=rekor)

    @abc.abstractmethod
    def sign(self, input_: IO[bytes]) -> KeySigningResult:
        """Base method for implementing key-signing."""
        raise NotImplementedError


class KeyRefSigner(BaseKeySigner):
    """Signer from a local or remote private key file."""

    def __init__(
        self,
        rekor: RekorClient,
        key_file: str,
    ) -> None:
        """Initialize a KeyRefSigner instance."""
        super().__init__(rekor=rekor)
        self.key_file = key_file

    # def sign(self, input_: IO[bytes]) -> KeySigningResult:
    #     """Sign using a private key."""
    #     return None


class NewKeySigner(BaseKeySigner):
    """Signer that generates a new pair of keys."""

    def __init__(
        self,
        rekor: RekorClient,
        key_file_prefix: Optional[str] = None,
        encryption_password: Optional[bool] = True,
    ) -> None:
        """Initialize a NewKeySigner instance."""
        super().__init__(rekor=rekor)
        self.key_file_prefix = key_file_prefix
        self.encryption_password = encryption_password

    def sign(self, input_: IO[bytes]) -> KeySigningResult:
        """Generate a new key pair and sign artifact."""
        input_digest = sha256_streaming(input_)
        logger.debug("Generating a key pair...")
        private_key = ec.generate_private_key(ec.SECP384R1())

        artifact_signature = private_key.sign(
            input_digest, ec.ECDSA(Prehashed(hashes.SHA256()))
        )

        if self.encryption_password:
            # Prompt for encryption password
            password = getpass.getpass(
                "Enter an encryption password for the private key:\n"
            ).encode()

        with open(f"{self.key_file_prefix}.key", "wb") as privkey_file:
            privkey_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        password
                    ),
                )
            )

        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with open(f"{self.key_file_prefix}.pub", "wb") as pubkey_file:
            pubkey_file.write(public_key)

        b64_artifact_signature = B64Str(base64.b64encode(artifact_signature).decode())
        b64_public_key = B64Str(base64.b64encode(public_key).decode())

        # Create the transparency log entry
        entry = self._rekor.log.entries.post(
            b64_artifact_signature=B64Str(b64_artifact_signature),
            sha256_artifact_hash=input_digest.hex(),
            b64_cert=b64_public_key,
        )

        logger.debug(f"Transparency log entry created at index: {entry.log_index}")

        return KeySigningResult(
            input_digest=HexStr(input_digest.hex()),
            # Workaround to include the public key instead of the signing certificate in the SigningResult
            public_key=b64_public_key,
            b64_signature=B64Str(b64_artifact_signature),
            log_entry=entry,
        )

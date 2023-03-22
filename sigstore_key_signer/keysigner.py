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
import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from pathlib import Path
from pydantic import BaseModel
from sigstore._internal.rekor import RekorClient
from sigstore._internal.tuf import TrustUpdater
from sigstore._utils import (
    B64Str,
    HexStr,
    sha256_streaming,
)
from sigstore.transparency import LogEntry
from sigstore_key_signer import DEFAULT_KEY_FILE_PREFIX
from sigstore_key_signer.adapters import (
    BaseAdapter,
    Vault,
    VAULT_ENV,
)
from typing import (
    IO,
    Optional,
    Type,
    TypeVar,
)
from urllib.parse import urlparse


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
    def production(cls: Type[T], **kwargs) -> T:
        """
        Return a key signer instance configured against Sigstore's production-level services.
        """
        updater = TrustUpdater.production()
        rekor = RekorClient.production(updater)
        return cls(rekor=rekor, **kwargs)

    @abc.abstractmethod
    def sign(self, input_: IO[bytes]) -> KeySigningResult:
        """Base method for implementing key-signing."""
        raise NotImplementedError


class KeyRefSigner(BaseKeySigner):
    """Signer from a local or remote private key file."""

    def __init__(
        self,
        rekor: RekorClient,
        key_path: Path,
        encryption_password: Optional[bytes],
    ) -> None:
        """Initialize a KeyRefSigner instance."""
        super().__init__(rekor=rekor)
        self.key_path = key_path
        self.encryption_password = encryption_password

    def _get_scheme(self) -> str:
        """Get the `key_path` URI or local path scheme."""
        return urlparse(self.key_path.as_posix()).scheme

    def _kms_adapter_from_scheme(self, scheme: str) -> BaseAdapter:
        """Retrieve a KMS adapter from provided scheme."""
        if scheme == "hashivault":
            # For Vault, the server address is set via the environment variable `VAULT_ADDR`
            return Vault()

        raise ValueError(f"Unknown KMS provider scheme: {scheme}")

    def sign(self, input_: IO[bytes]) -> KeySigningResult:
        """Sign using a private key."""
        logger.debug(f"Retrieving a signing key from {self.key_path}...")
        scheme = self._get_scheme()
        input_digest = sha256_streaming(input_)

        # Key file is in a local path
        if scheme == "":
            with open(self.key_path, "rb") as file:
                signing_key = file.read()

                decrypted_key: ec.EllipticCurvePrivateKey = serialization.load_pem_private_key(  # type: ignore
                    data=signing_key,
                    password=self.encryption_password,
                )
                artifact_signature = decrypted_key.sign(
                    input_digest,
                    ec.ECDSA(Prehashed(hashes.SHA256())),
                )
                public_key = decrypted_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )

                b64_artifact_signature = B64Str(
                    base64.b64encode(artifact_signature).decode()
                )
                b64_public_key = B64Str(base64.b64encode(public_key).decode())

        else:
            kms_client = self._kms_adapter_from_scheme(self._get_scheme())
            privkey_name = self.key_path.as_posix().split("://")[-1]
            if isinstance(kms_client, Vault):
                artifact_signature = kms_client.sign(
                    privkey_name,
                    input_digest,
                )
            # Retrieve the corresponding public key
            public_key = kms_client.retrieve(privkey_name)
            b64_artifact_signature = B64Str(artifact_signature)
            b64_public_key = B64Str(public_key)

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


class NewKeySigner(BaseKeySigner):
    """Signer that generates a new pair of keys."""

    def __init__(
        self,
        rekor: RekorClient,
        key_file_prefix: str,
        encryption_password: Optional[bytes],
    ) -> None:
        """Initialize a NewKeySigner instance."""
        super().__init__(rekor=rekor)
        self.key_file_prefix = key_file_prefix or DEFAULT_KEY_FILE_PREFIX
        self.encryption_password = encryption_password

    def sign(self, input_: IO[bytes]) -> KeySigningResult:
        """Generate a new key pair and sign artifact."""
        input_digest = sha256_streaming(input_)
        logger.debug("Generating a key pair...")
        private_key = ec.generate_private_key(ec.SECP384R1())

        artifact_signature = private_key.sign(
            input_digest, ec.ECDSA(Prehashed(hashes.SHA256()))
        )

        encryption_algorithm: serialization.KeySerializationEncryption

        if self.encryption_password:
            encryption_algorithm = serialization.BestAvailableEncryption(
                self.encryption_password
            )

        else:
            encryption_algorithm = serialization.NoEncryption()

        with open(f"{self.key_file_prefix}.key", "wb") as privkey_file:
            privkey_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption_algorithm,
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

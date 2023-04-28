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

from asn1crypto.core import Sequence, Integer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
)
from pathlib import Path
from pydantic import BaseModel
from sigstore._internal.rekor import RekorClient
from sigstore._internal.rekor.client import RekorClientError
from sigstore._internal.tuf import TrustUpdater
from sigstore._utils import (
    B64Str,
    HexStr,
    sha256_streaming,
)
from sigstore.transparency import LogEntry
from sigstore_key_signer import (
    DEFAULT_KEY_FILE_PREFIX,
    KMS_PROVIDERS_MAP,
)
from sigstore_key_signer.adapters.base import BaseAdapter
from sigstore_key_signer.adapters.vault import (
    Vault,
    VAULT_ENV,
)
from sigstore_key_signer.generate import (
    generate_key_pair,
    store_local_key_pair,
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
    def sign(self, input_: IO[bytes] | str, *args, **kwargs) -> KeySigningResult:
        """Base method for implementing key-signing."""
        raise NotImplementedError


class KeyRefSigner(BaseKeySigner):
    """Signer from a local or remote private key file."""

    def __init__(
        self, key_path: str, rekor: RekorClient, encryption_password: bytes
    ) -> None:
        """Initialize a KeyRefSigner instance."""
        super().__init__(rekor=rekor)
        self.key_path = key_path
        self.encryption_password = encryption_password

    @property
    def is_local(self) -> bool:
        """Determine if the key path provided is local or remote."""
        parsed_path = urlparse(self.key_path)
        if parsed_path.scheme:
            return False
        return True

    @property
    def instance(self) -> "KeyRefSigner":
        """Return a KeyRefSigner subclass for local or remote signing."""
        if self.is_local:
            return LocalKeySigner(
                key_path=self.key_path,
                rekor=self._rekor,
                encryption_password=self.encryption_password,
            )

        return RemoteKeySigner(
            key_path=self.key_path,
            rekor=self._rekor,
        )

    def sign(self, input_: IO[bytes] | str, *args, **kwargs) -> KeySigningResult:
        """Delegate signing to the adapted KeyRefSigner child instance."""
        return self.instance.sign(input_, *args, **kwargs)


class LocalKeySigner(KeyRefSigner):
    """Signer from an existing local key pair."""

    def __init__(
        self,
        key_path: str,
        rekor: RekorClient,
        encryption_password: Optional[bytes],
    ) -> None:
        """Initialize a LocalKeySigner instance."""
        super().__init__(
            key_path=key_path, rekor=rekor, encryption_password=encryption_password
        )
        self.key_path = key_path
        self.encryption_password = encryption_password

    def sign(self, input_: IO[bytes], *args, **kwargs) -> KeySigningResult:
        """Sign an artifact bytes with a local key pair."""
        input_digest = sha256_streaming(input_)
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

        # Create the transparency log entry
        entry = self._rekor.log.entries.post(
            b64_artifact_signature=b64_artifact_signature,
            sha256_artifact_hash=input_digest.hex(),
            b64_cert=b64_public_key,
        )

        logger.debug(f"Transparency log entry created at index: {entry.log_index}")

        return KeySigningResult(
            input_digest=HexStr(input_digest.hex()),
            # Workaround to include the public key instead of the signing certificate in the SigningResult
            public_key=b64_public_key,
            b64_signature=b64_artifact_signature,
            log_entry=entry,
        )


class RemoteKeySigner(KeyRefSigner):
    """Signer from a remote KMS."""

    def __init__(self, key_path: str, rekor: RekorClient) -> None:
        """Initialize a RemoteKeySigner instance."""
        super().__init__(key_path=key_path, rekor=rekor, encryption_password=None)
        self.key_path = key_path

    @property
    def key_store_path(self) -> str:
        """Retrieve the key storage path from the KMS URI."""
        return urlparse(self.key_path).netloc

    def adapter_from_scheme(self) -> BaseAdapter:
        """Get a KMS adapter from the specified scheme."""
        scheme = urlparse(self.key_path).scheme
        try:
            adapter = KMS_PROVIDERS_MAP[scheme]
        except KeyError as keyerror:
            logger.error(f"No KMS found for URI scheme {scheme}")
            raise keyerror

        return adapter()

    def sign(self, input_: IO[bytes], *args, **kwargs) -> KeySigningResult:
        """Sign an artifact with a key stored in a KMS."""
        logger.debug(f"Retrieving a signing key from {self.key_path}")
        kms_client = self.adapter_from_scheme()
        input_digest = sha256_streaming(input_)

        signature = kms_client.sign(
            self.key_store_path,
            base64.b64encode(input_digest).decode(),
        )

        b64_artifact_signature = B64Str(base64.b64encode(signature).decode())

        public_key_bytes = kms_client.retrieve_public_key(self.key_store_path)
        b64_public_key = B64Str(base64.b64encode(public_key_bytes).decode())

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

    def sign(
        self, input_: IO[bytes], encryption_password: Optional[bytes]
    ) -> KeySigningResult:
        """Generate a new key pair and sign artifact."""
        input_digest = sha256_streaming(input_)
        private_key, public_key = generate_key_pair()

        artifact_signature = private_key.sign(
            input_digest, ec.ECDSA(Prehashed(hashes.SHA256()))
        )

        privkey_bytes, pubkey_bytes = store_local_key_pair(
            private_key,
            public_key,
            self.key_file_prefix,
            encryption_password,
        )

        b64_artifact_signature = B64Str(base64.b64encode(artifact_signature).decode())
        b64_public_key = B64Str(base64.b64encode(pubkey_bytes).decode())

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

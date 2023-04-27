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

"""Generate a new key pair."""

import logging
import os
import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Optional

from sigstore_key_signer.adapters import Vault
from sigstore_key_signer.exceptions import KMSProviderError


logger = logging.getLogger(__name__)

KMS_PROVIDERS_MAP = {
    "hashivault": Vault,
}


# TODO: dedupe this logic with the one for `NewKeySigner`
def generate_key_pair(
    prefix: str,
    password: Optional[bytes],
) -> tuple[bytes, bytes]:
    """Generate a new key pair."""
    logger.debug("Generating a key pair...")
    private_key = ec.generate_private_key(ec.SECP384R1())
    encryption: serialization.KeySerializationEncryption

    if password:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return (private_key_bytes, public_key_bytes)


def generate_local_key_pair(
    prefix: str,
    path: str,
    password: Optional[bytes],
) -> tuple[bytes, bytes]:
    """Generate a new key pair locally."""
    privkey_bytes, pubkey_bytes = generate_key_pair(prefix=prefix, password=password)

    with open(os.path.join(path, f"{prefix}.key"), "wb") as privkey_file:
        privkey_file.write(privkey_bytes)

    with open(os.path.join(path, f"{prefix}.pub"), "wb") as pubkey_file:
        pubkey_file.write(pubkey_bytes)

    return privkey_bytes, pubkey_bytes


def generate_to_kms(
    prefix: str,
    path: str,
    kms_scheme: str,
) -> bytes:
    """Generate a new key pair and store it in a KMS."""
    try:
        kms_adapter = KMS_PROVIDERS_MAP[kms_scheme]
    except KeyError as e:
        logger.error(
            f"Error: KMS provider not found: {kms_scheme}"
        )
        raise e

    try:
        kms = kms_adapter()
        pubkey_name, privkey_name = f"{prefix}.pub", f"{prefix}.key"
        response = kms.store(privkey_name)
        response.raise_for_status()
    except requests.HTTPError as http_error:
        raise KMSProviderError from http_error

    pubkey = kms.retrieve_public_key(privkey_name)

    with open(os.path.join(path, pubkey_name), "w") as pubkey_file:
        pubkey_file.write(pubkey)
        logger.info(f"Public key written to {pubkey_name}")

    return pubkey
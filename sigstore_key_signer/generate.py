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

from sigstore_key_signer import KMS_PROVIDERS_MAP
from sigstore_key_signer.adapters.vault import Vault
from sigstore_key_signer.exceptions import KMSProviderError


logger = logging.getLogger(__name__)


def generate_key_pair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a new key pair."""
    logger.debug("Generating a key pair...")
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    return (private_key, public_key)


def store_local_key_pair(
    privkey: ec.EllipticCurvePrivateKey,
    pubkey: ec.EllipticCurvePublicKey,
    prefix: str,
    password: Optional[bytes],
) -> tuple[bytes, bytes]:
    """Generate a new key pair locally."""
    encryption: serialization.KeySerializationEncryption
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()

    privkey_bytes = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    pubkey_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    privkey_path, pubkey_path = (
        f"{prefix}.key",
        f"{prefix}.pub",
    )

    with open(privkey_path, "wb") as privkey_file:
        privkey_file.write(privkey_bytes)

    with open(pubkey_path, "wb") as pubkey_file:
        pubkey_file.write(pubkey_bytes)

    logger.debug(f"Public key file written at {pubkey_path}")

    return privkey_bytes, pubkey_bytes


def generate_to_kms(
    prefix: str,
    kms_scheme: str,
) -> bytes:
    """Generate a new key pair and store it in a KMS."""
    try:
        kms_adapter = KMS_PROVIDERS_MAP[kms_scheme]
    except KeyError as e:
        logger.error(f"Error: KMS provider not found: {kms_scheme}")
        raise e

    try:
        kms = kms_adapter()
        if not prefix.endswith(".key"):
            pubkey_name = f"{prefix}.pub"
            privkey_name = f"{prefix}.key"
        else:
            pubkey_name = f"{prefix[:-4]}.pub"
            privkey_name = prefix
        logger.debug(
            f"Generating new signing key {privkey_name} in KMS {kms.__class__.__name__}"
        )
        response = kms.store(privkey_name)
        response.raise_for_status()
    except requests.HTTPError as http_error:
        raise KMSProviderError from http_error

    pubkey = kms.retrieve_public_key(privkey_name)

    with open(pubkey_name, "wb") as pubkey_file:
        pubkey_file.write(pubkey)
        logger.info(f"Public key written to {pubkey_name}")

    return pubkey

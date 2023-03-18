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

import getpass
import logging
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


logger = logging.getLogger(__name__)


# TODO: dedupe this logic with the one for `NewKeySigner`
def generate_key_pair(
    prefix: str,
    path: str,
    no_password: bool,
) -> tuple[bytes, bytes]:
    """Generate a new key pair."""
    logger.debug("Generating a key pair...")
    private_key = ec.generate_private_key(ec.SECP384R1())
    encryption: serialization.KeySerializationEncryption

    if not no_password:
        # Prompt for encryption password
        passwd = getpass.getpass(
            "Enter an encryption password for the private key:\n"
        ).encode()
        encryption = serialization.BestAvailableEncryption(passwd)
    else:
        encryption = serialization.NoEncryption()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    with open(os.path.join(path, f"{prefix}.key"), "wb") as privkey_file:
        privkey_file.write(private_key_bytes)

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(os.path.join(path, f"{prefix}.pub"), "wb") as pubkey_file:
        pubkey_file.write(public_key)

    return (private_key_bytes, public_key)

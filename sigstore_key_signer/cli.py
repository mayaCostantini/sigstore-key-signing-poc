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
CLI for interacting with Sigstore key-signing PoC,
aimed to extend the capabilities provided by the sigstore-python CLI
without implementing all the capabilities 
"""

from __future__ import annotations

import argparse
import base64
import logging
import os
import sys

from pathlib import Path
from sigstore_key_signer import (
    DEFAULT_KEY_FILE_PREFIX,
    __version__,
)
from sigstore_key_signer.exceptions import (
    SigstoreKeySignerException,
    VerificationError,
)
from sigstore_key_signer.generate import generate_key_pair
from sigstore_key_signer.keysigner import (
    BaseKeySigner,
    KeyRefSigner,
    NewKeySigner,
)
from sigstore_key_signer.keyverifier import (
    BaseKeyVerifier,
    KeyRekorClient,
    KeyRefVerifier,
    KeyVerificationMaterials,
)
from sigstore._internal.ctfe import CTKeyring
from sigstore._internal.keyring import Keyring
from sigstore._internal.rekor.client import (
    DEFAULT_REKOR_URL,
    RekorKeyring,
)
from sigstore._internal.tuf import TrustUpdater
from sigstore.transparency import LogEntry
from sigstore.verify.models import VerificationFailure
from typing import TextIO


logging.basicConfig()
logger = logging.getLogger(__name__)


def _rekor_client_from_opts(args: argparse.Namespace) -> KeyRekorClient:
    """Construct a KeyRekorClient from command line options."""
    if args.rekor_url == DEFAULT_REKOR_URL:
        if args.rekor_root_pubkey is not None:
            rekor_keys = [args.rekor_root_pubkey.read()]
        else:
            updater = TrustUpdater.production()
            rekor_keys = updater.get_rekor_keys()

    return KeyRekorClient(
        url=args.rekor_url,
        rekor_keyring=RekorKeyring(Keyring(rekor_keys)),
        # We don't use the CT keyring in verification so we can supply an empty keyring
        ct_keyring=CTKeyring(Keyring()),
    )


def _signer_from_opts(args: argparse.Namespace) -> BaseKeySigner:
    """Choose a Key Signer from command line options."""
    if args.key:
        key_ref_signer = KeyRefSigner.production()
        key_ref_signer.key_file = args.key_file
        return key_ref_signer
    if args.rekor_url == DEFAULT_REKOR_URL:
        new_key_signer = NewKeySigner(rekor=_rekor_client_from_opts(args))
    else:
        new_key_signer = NewKeySigner.production()
    new_key_signer.key_file_prefix = args.key_file_prefix
    new_key_signer.encryption_password = args.password

    return new_key_signer


def _verifier_from_opts(args: argparse.Namespace) -> BaseKeyVerifier:
    """Choose a Key Verifier from command line options."""
    if args.rekor_url == DEFAULT_REKOR_URL:
        return KeyRefVerifier.production()
    else:
        return KeyRefVerifier(rekor=_rekor_client_from_opts(args))


def _sign_key(args: argparse.Namespace) -> None:
    """Sign with a self-managed key pair."""
    output_map = {}
    for file in args.files:
        if not file.is_file():
            args._parser.error(f"Input must be a file: {file}")

    if not args.output_signature:
        sig = file.parent / f"{file.name}.sig"

    if not args.overwrite:
        if sig and sig.exists():
            args._parser.error(
                f"Refusing to overwrite output signature file {sig} without --overwrite"
            )

    output_map[file] = {
        "sig": sig,
    }

    signer = _signer_from_opts(args)

    for file, outputs in output_map.items():
        logger.debug(f"signing for {file.name}")
        with file.open(mode="rb", buffering=0) as io:
            result = signer.sign(
                input_=io,
            )

        print(f"Transparency log entry created at index: {result.log_entry.log_index}")

        sig_output: TextIO
        if outputs["sig"] is not None:
            sig_output = outputs["sig"].open("w")
        else:
            sig_output = sys.stdout

        print(result.b64_signature, file=sig_output)

        if outputs["sig"] is not None:
            print(f"Signature written to {outputs['sig']}")


def _collect_verification_materials(
    args: argparse.Namespace,
) -> tuple[BaseKeyVerifier, list[tuple[Path, KeyVerificationMaterials]]]:
    """Collect input files and verification materials (signature, public key)."""
    input_map = {}
    for file in args.files:
        if not file.is_file():
            args._parser.error(f"Input must be a file: {file}")

        sig, pubkey = (args.signature, args.public_key)

        if args.signature is None:
            sig = file.parent / f"{file.name}.sig"

        if args.public_key is None:
            pubkey = file.parent / f"{DEFAULT_KEY_FILE_PREFIX}.pub"

        missing = []
        if args.signature or args.public_key:
            if args.signature:
                if not sig.is_file():
                    missing.append(str(sig))

            if args.public_key:
                if not pubkey.is_file():
                    missing.append(str(pubkey))

        input_map[file] = {"sig": sig, "public_key": pubkey}

        if missing:
            args._parser.error(
                f"Missing verification materials for {(file)}: {', '.join(missing)}"
            )

    verifier = _verifier_from_opts(args)

    all_materials = []
    for file, inputs in input_map.items():
        signature: bytes
        public_key: bytes
        entry: LogEntry | None = None

        # Load the signature
        logger.debug(f"Using signature from: {inputs['sig']}")
        b64_signature = inputs["sig"].read_text()
        signature = base64.b64decode(b64_signature)

        logger.debug(f"Using public key from {inputs['public_key']}")
        public_key = inputs["public_key"].read_bytes()

        with file.open(mode="rb", buffering=0) as io:
            materials = KeyVerificationMaterials(
                input_=io,
                signature=signature,
                public_key=public_key,
                rekor_entry=entry,
            )

        logger.debug(f"Verifying contents from: {file}")

        with file.open(mode="rb", buffering=0) as io:
            all_materials.append((file, materials))

    return (verifier, all_materials)


def _verify_key(args: argparse.Namespace) -> None:
    """Verify a signature produced by a self-managed key pair."""

    verifier, file_with_materials = _collect_verification_materials(args)

    for file, materials in file_with_materials:
        result = verifier.verify(
            materials=materials,
        )

        if isinstance(result, VerificationFailure):
            print(f"Failed to verify signature for {file.name}")
            raise VerificationError

        else:
            print(f"Verified signature for {file.name}: OK.")


def _generate_key_pair(args: argparse.Namespace) -> None:
    """Generate a new key pair."""
    privpath = Path(args.path) / f"{args.output_key_prefix}.pub"
    pubpath = Path(args.path) / f"{args.output_key_prefix}.key"
    if (privpath.is_file() or pubpath.is_file()) and not args.overwrite:
        args._parser.error(
            f"Refusing to overwrite output key files {args.output_key_prefix}.* without --overwrite"
        )
    generate_key_pair(
        prefix=args.output_key_prefix,
        path=args.path,
        no_password=args.no_password,
    )


def _parser() -> argparse.ArgumentParser:
    """
    Main parser for sigstore-key-signer.
    Instance and output options are not configurable
    for simplification purposes.
    """
    parser = argparse.ArgumentParser(
        prog="sigstore-key-signer",
        description="a tool for signing and verifying Python package distributions",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity",
    )
    global_instance_options = parser.add_argument_group("Sigstore instance options")
    global_instance_options.add_argument(
        "--rekor-url",
        metavar="URL",
        type=str,
        default=os.getenv("SIGSTORE_REKOR_URL", DEFAULT_REKOR_URL),
        help="The Rekor instance to use",
    )
    global_instance_options.add_argument(
        "--rekor-root-pubkey",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="A PEM-encoded root public key for Rekor itself",
        default=os.getenv("SIGSTORE_REKOR_ROOT_PUBKEY"),
    )

    subcommands = parser.add_subparsers(required=True, dest="subcommand")
    sign = subcommands.add_parser(
        "sign-key", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    sign.add_argument(
        "-k",
        "--key",
        metavar="PATH",
        type=Path,
        help="The path to a local or remote private key file",
    )
    sign.add_argument(
        "-o",
        "--output-signature",
        metavar="FILE",
        type=Path,
        help="Path to output signature file",
    )
    sign.add_argument(
        "-p",
        "--key-file-prefix",
        metavar="NAME",
        type=str,
        default=DEFAULT_KEY_FILE_PREFIX,
        help="Prefix name for new key files",
    )
    sign.add_argument(
        "-w",
        "--password",
        action="store_true",
        default=True,
        help="Set an encryption password for the generated private key file",
    )
    sign.add_argument(
        "--overwrite",
        action="store_true",
        default=False,
        help="Overwrite preexisting signature if present",
    )
    sign.add_argument(
        "files",
        metavar="FILE",
        type=Path,
        nargs="+",
        help="The files to sign",
    )

    verify = subcommands.add_parser(
        "verify-key", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    verify.add_argument(
        "-k",
        "--public-key",
        metavar="PATH",
        type=Path,
        help="The path to a local or remote public key file",
    )
    verify.add_argument(
        "-s",
        "--signature",
        metavar="SIGNATURE",
        type=Path,
        help="Signature path or remote URL",
    )
    verify.add_argument(
        "files",
        metavar="FILE",
        type=Path,
        nargs="+",
        help="The files to verify",
    )

    generate_key_pair = subcommands.add_parser(
        "generate-key-pair", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    generate_key_pair.add_argument(
        "-p",
        "--path",
        metavar="PATH",
        type=Path,
        default=Path("."),
        help="Path for generating a key pair",
    )
    generate_key_pair.add_argument(
        "-o",
        "--output-key-prefix",
        metavar="mykey",
        default="sigstore",
        help="Prefix for the generated key files",
    )
    generate_key_pair.add_argument(
        "-W",
        "--no-password",
        action="store_false",
        default=False,
        help="Do not prompt for a private key encryption password",
    )
    generate_key_pair.add_argument(
        "--overwrite",
        action="store_true",
        default=False,
        help="Overwrite preexisting key files if present",
    )

    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()

    logger.debug(f"parsed arguments {args}")
    args._parser = parser

    try:
        if args.subcommand == "sign-key":
            _sign_key(args)

        elif args.subcommand == "verify-key":
            _verify_key(args)

        elif args.subcommand == "generate-key-pair":
            _generate_key_pair(args)

    except SigstoreKeySignerException as e:
        raise e


if __name__ == "__main__":
    main()

# sigstore-python key-signing Proof-of-Concept
A PoC for extending [`sigstore-python`](https://github.com/sigstore/sigstore-python) to sign file artifacts using a self-managed key pair.

**:warning: Warning: this tool is an early-stage prototype and is not ready for production use.**

## Motivation

The `sigstore-python` library currently signs artifacts using Sigstore's [keyless signing](https://docs.sigstore.dev/cosign/keyless/) workflow, which identifies users through an OpenID Connect (OIDC) provider.
However, some Python projects integrating Sigstore also need to provide the Sigstore [key-signing](https://docs.sigstore.dev/cosign/sign/) flow that uses a self-managed pair of keys, as currently supported in Cosign.

The aim of this tool is to provide a command-line interface and a library based on the original `sigstore-python` to enable Sigstore key-signing flows in Python projects.

## Usage

```
usage: sigstore-key-signer [-h] [-V] [-v] [--rekor-url URL] [--rekor-root-pubkey FILE] {sign,verify,generate-key-pair} ...

A tool for signing and verifying files artifatcs with Sigstore using a key pair

positional arguments:
  {sign,verify,generate-key-pair}

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -v, --verbose         Increase verbosity (default: 0)

Sigstore instance options:
  --rekor-url URL       The Rekor instance to use (default: https://rekor.sigstore.dev)
  --rekor-root-pubkey FILE
                        A PEM-encoded root public key for Rekor itself (default: None)

        Example usage:

        # Sign by generating a new local key pair
        sigstore-key-signer sign artifact.txt

        # Sign with an existing local key pair
        sigstore-key-signer sign --key sigstore.key artifact.txt

        # Sign using a key stored in Hashicorp Vault
        sigstore-key-signer sign --key hashivault://sigstore.key artifact.txt

        # Generate a new password-protected local key pair
        sigstore-key-signer generate-key-pair --password-stdin
```

Supported actions include:

- Generating a new pair of keys locally and using them to sign artifacts:

```
sigstore-key-signer sign --password my-private-key-password file.txt

Transparency log entry created at index: 16110633
Signature written to file.txt.sig
```

- Signing using an existing private key:

```
sigstore-key-signer sign --key sigstore.key --password my-private-key-password file.txt

Transparency log entry created at index: 16111291
Signature written to file.txt.sig
```

- Generating a new private key in Hashicorp Vault:

```
sigstore-key-signer generate-key-pair --kms hashivault://sigstore.key

Public key written to sigstore.pub
```

- Signing an artifact using an existing key stored in Hashicorp Vault:

```
sigstore-key-signer sign --key hashivault://sigstore.key file.txt

Transparency log entry created at index: 21762071
Signature written to file.txt.sig
```

- Verifying a signature using a local public key file:

```
sigstore-key-signer verify --public-key sigstore.pub file.txt

Verified signature for file.txt: OK.
```

## Development

To start the development environment for `sigstore-key-signer` with a Vault server in development mode, run:

```
docker-compose up
```

This command will start a Vault container, automatically enable the Transit engine used to store private keys and start a second container with the built from source version of `sigstore-key-signer` and Vault credentials available in the environment. To rebuild the `sigstore-key-signer` container, run `docker-compose up --build`.


## Future support

`sigstore-key-signer` plans on including support for signing artifacts with private keys stored on Key Management Services (KMS).
A KMS adapter for Hashicorp Vault is currently under development, and adapters will be available in the future for Google KMS and AWS KMS.

The current implementation includes a base adapater class `BaseAdapter` at [sigstore_key_signer/adapters/base.py](https://github.com/mayaCostantini/sigstore-key-signing-poc/blob/main/sigstore_key_signer/adapters/base.py) providing a common interface for KMS.
If you wish to implement support for a specific KMS, please open a Pull Request at [sigstore-key-signing-poc/pulls](https://github.com/mayaCostantini/sigstore-key-signing-poc/pulls). The adapter must subclass `BaseAdapter` and provide the `uri_scheme` property and the `store`, `retrieve`, `delete` and `sign` methods.

An integration with [PKCS#11](https://en.wikipedia.org/wiki/PKCS_11)-compliant keystores is also on the roadmap for this project.

## Contribute

The project is still in an early development stage, contributions are welcome. Before contributing, make sure you read the [contribution guidelines](https://github.com/mayaCostantini/sigstore-key-signing-poc/blob/main/CONTRIBUTING.md).

For raising a bug, proposing a feature or starting a discussion, fill an issue at [sigstore-key-signing-poc/issues](https://github.com/mayaCostantini/sigstore-key-signing-poc/issues).

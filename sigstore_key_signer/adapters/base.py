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

"""Base class for implementing KMS adapters."""

import abc

from typing import Any


class BaseAdapter(abc.ABC):
    """Parent class for secrets manager adapters."""

    def __init__(self, *args, **kwargs) -> None:
        """Initialize a KMS adapter."""
        raise NotImplementedError

    @abc.abstractmethod
    def store(self, *args, **kwargs) -> Any:
        """Store a key."""
        raise NotImplementedError

    @abc.abstractmethod
    def retrieve_public_key(self, *args, **kwargs) -> Any:
        """Retrieve a public key."""
        raise NotImplementedError

    @abc.abstractmethod
    def delete(self, *args, **kwargs) -> Any:
        """Delete a key."""
        raise NotImplementedError

    @abc.abstractmethod
    def sign(self, *args, **kwargs) -> Any:
        """Sign using a private key stored by the KMS."""
        raise NotImplementedError

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

"""Exceptions for sigstore-key-signer PoC."""


class SigstoreKeySignerException(Exception):
    """High-level sigstore-key-signer exception."""


class VerificationError(SigstoreKeySignerException):
    """Exception raised when a signature verification fails."""


class KeyNotInitializedException(SigstoreKeySignerException):
    """Exception raised when a Key has not been initialized with a card attribute."""


class SlotNotSetException(SigstoreKeySignerException):
    """Exception raised when the slot for a Key is unset."""


class SlotNotFoundException(SigstoreKeySignerException):
    """Exception raised when no slot could be identified on a device by a SecurityKeySigner."""

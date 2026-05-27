# Copyright 2025 University of Southern California
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import annotations # pragma: no cover
from enum import Enum  # pragma: no cover
from typing import cast  # pragma: no cover


class OAuthError(str, Enum):  # pragma: no cover
    """
    Small set of canonical (short) OAuth-ish error codes with human-friendly descriptions.
    Purpose: adapters raise AdapterAuthError with `error_code` set to one of these .code values.
    The token endpoint / caller can map these to RFC-compliant responses.
    """
    UNKNOWN_ERROR = (
        "unknown_error",
        "An unknown error occurred while attempting to access this resource."
    )
    SERVER_ERROR = (
        "server_error",
        "The server encountered an error while attempting to process this request."
    )
    INVALID_REQUEST = (
        "invalid_request",
        "The request is missing a required parameter, includes an unsupported parameter, or is malformed."
    )
    INVALID_TARGET = (
        "invalid_target",
        "The requested resource is invalid, missing, unknown, or malformed."
    )
    INVALID_GRANT = (
        "invalid_grant",
        "The provided authorization grant or refresh token is invalid, expired, revoked, or mismatched."
    )
    INVALID_TOKEN = (
        "invalid_token",
        "The provided token is invalid, expired, or otherwise unacceptable."
    )
    INSUFFICIENT_SCOPE = (
        "insufficient_scope",
        "The token does not grant the required scope to access the requested resource."
    )
    ACCESS_DENIED = (
        "access_denied",
        "The authenticated principal is not authorized to perform the requested action."
    )
    UNAUTHORIZED_CLIENT = (
        "unauthorized_client",
        "The client is not authorized to use this grant type or perform this operation."
    )
    TEMPORARILY_UNAVAILABLE = (
        "temporarily_unavailable",
        "A transient backend or transport error occurred; try again later."
    )

    def __new__(cls, code: str, description: str) -> OAuthError:
        obj = cast("OAuthError", str.__new__(cls, code))
        obj._value_ = code
        obj._description_ = description
        return obj

    @property
    def code(self) -> str:
        # explicit convenience accessor (same as .value)
        return self.value

    @property
    def description(self) -> str:
        return self._description_

    def __str__(self) -> str:
        return f"{self.code}: {self.description}"

    @classmethod
    def get(cls, code: str) -> OAuthError:
        """
        Return the OAuthError matching `code` or a safe fallback (UNKNOWN_ERROR) if not found.
        """
        try:
            return cls(code)
        except ValueError:
            return cls.UNKNOWN_ERROR

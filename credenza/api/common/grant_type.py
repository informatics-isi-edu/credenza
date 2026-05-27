#
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
from __future__ import annotations
import enum
from ..session.storage.session_store import SessionType


class GrantType(str, enum.Enum):
    # Core OAuth 2.0
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"
    PASSWORD = "password"  # legacy / currently unsupported

    # Extensions
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
    TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"

    # Assertions
    JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    SAML2_BEARER = "urn:ietf:params:oauth:grant-type:saml2-bearer"

    @classmethod
    def _missing_(cls, value: object):
        # Accept short-form aliases for grant types whose canonical values are URNs.
        # This allows config files to use "device_code" instead of the full URN.
        _aliases = {
            "device_code":   cls.DEVICE_CODE,
            "token_exchange": cls.TOKEN_EXCHANGE,
            "jwt_bearer":    cls.JWT_BEARER,
            "saml2_bearer":  cls.SAML2_BEARER,
        }
        if isinstance(value, str):
            return _aliases.get(value.strip())
        return None  # pragma: no cover

    @classmethod
    def from_value(cls, value: str) -> GrantType:  # pragma: no cover
        try:
            return cls(value)
        except ValueError:
            raise ValueError(f"Unsupported grant_type: {value}")


def map_grant_type_to_session_type(grant_type: GrantType) -> SessionType:
    try:
        return {
            GrantType.CLIENT_CREDENTIALS: SessionType.SERVICE,
            GrantType.DEVICE_CODE: SessionType.DEVICE,
            GrantType.TOKEN_EXCHANGE: SessionType.DERIVED,
            GrantType.AUTHORIZATION_CODE: SessionType.USER,
          # GrantType.REFRESH_TOKEN: SessionType.USER,  # not currently applicable
        }[grant_type]
    except KeyError:  # pragma: no cover
        raise ValueError(f"Unsupported grant type for session mapping: {grant_type}")
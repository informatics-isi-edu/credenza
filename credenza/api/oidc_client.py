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
import os
import json
import time
import requests
import logging
from secrets import token_urlsafe
from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import jwt, JsonWebKey

logger = logging.getLogger(__name__)

class OIDCClientFactory:
    def __init__(self, profile_map):
        """
        Initialize the factory with a map of realm -> profile dicts.
        Each profile should include client_id, client_secret, discovery_url or manual endpoints.
        """
        self.profile_map = profile_map
        self._client_cache = {}

    def get_client(self, realm, native_client=False):
        if realm not in self.profile_map:
            raise ValueError(f"Unknown realm: {realm}")
        cache_key = realm if not native_client else realm + "_native"
        if cache_key not in self._client_cache:
            profile = self.profile_map[realm]
            self._client_cache[cache_key] = OIDCClient(profile, native_client)
        return self._client_cache[cache_key]


class OIDCClient:
    def __init__(self, profile, native_client=False):
        self.client_secret_file = profile["client_secret_file"]
        self.scope = profile.get("scopes", "openid email profile")
        self.redirect_uri = profile.get("redirect_uri")
        self.profile = profile
        self.native_client = native_client

        discovery_url = profile.get("discovery_url")
        metadata = {}
        if discovery_url:
            metadata = self._fetch_discovery_metadata(discovery_url)

        # Pick each endpoint from profile first, then fall back to metadata
        self.authorize_url = profile.get("authorize_url") or metadata.get("authorization_endpoint")
        self.token_url = profile.get("token_url") or metadata.get("token_endpoint")
        self.revocation_url = profile.get("revocation_url") or metadata.get("revocation_endpoint")
        self.userinfo_url = profile.get("userinfo_url") or metadata.get("userinfo_endpoint")
        self.introspect_url = profile.get("introspect_url") or metadata.get("introspection_endpoint")
        self.jwks_uri = profile.get("jwks_uri") or metadata.get("jwks_uri")
        self.issuer = profile.get("issuer", metadata.get("issuer", "")).rstrip("/")

        self.jwks = None
        self._jwks_fetched_at = None

        self._load_client_secret()

    def _load_client_secret(self):
        logger.debug(f"Loading client secret from: {self.client_secret_file}")
        if os.path.exists(self.client_secret_file):
            with open(self.client_secret_file) as f:
                client = json.load(f)
                native_client_id = client.get("native_client_id")
                if self.native_client and native_client_id:
                    self.client_id = client["native_client_id"]
                    self.client_secret = None
                else:
                    self.client_id = client["client_id"]
                    self.client_secret = client["client_secret"]
        else:
            raise ValueError(f"Client secret file does not exist: {self.client_secret_file}")

    @staticmethod
    def _fetch_discovery_metadata(url):
        response = requests.get(url)
        response.raise_for_status()
        return response.json()

    def _jwks_expired(self, ttl=86400):
        return not self._jwks_fetched_at or (time.time() - self._jwks_fetched_at > ttl)

    def _load_jwks(self):
        if not self.jwks_uri:
            raise ValueError("JWKs URI not configured for issuer")
        if not self.jwks or self._jwks_expired():
            logger.debug("Fetching new JWKs from: %s", self.jwks_uri)
            resp = requests.get(self.jwks_uri)
            resp.raise_for_status()
            self.jwks = JsonWebKey.import_key_set(resp.json())
            self._jwks_fetched_at = time.time()
            for k in self.jwks.keys:
                key = k.as_dict()
                logger.debug(f"Loaded JWK kid={key.get('kid')}, alg={key.get('alg')}")

    def create_authorization_url(self, use_pkce, is_device=False, **kwargs):
        """
        Builds the /authorize URL.  If use_pkce=True, Authlib will
        auto-generate a code_verifier & code_challenge.
        Returns (url, state, code_verifier).
        """
        extra = kwargs or {}
        scope = self.scope + " offline_access" if is_device and "offline_access" not in self.scope else None
        session = self.get_oauth_session(
            code_challenge_method='S256' if use_pkce else None,
            scope=scope
        )
        code_verifier = token_urlsafe(64) if use_pkce else None
        url, state = session.create_authorization_url(
            self.authorize_url,
            **{"code_verifier": code_verifier} if code_verifier else {},
            **extra
        )
        return url, state, code_verifier

    def get_oauth_session(self,
                          scope=None,
                          redirect_uri=None,
                          token=None,
                          code_challenge_method=None):
        return OAuth2Session(
            client_id=self.client_id,
            client_secret=self.client_secret,
            scope=scope or self.scope,
            redirect_uri=redirect_uri or self.redirect_uri,
            token=token,
            code_challenge_method=code_challenge_method
        )

    def exchange_code_for_tokens(self, code, redirect_uri, code_verifier):
        client = self.get_oauth_session()
        try:
            token = client.fetch_token(
                url=self.token_url,
                grant_type="authorization_code",
                code=code,
                redirect_uri=redirect_uri or self.redirect_uri,
                **({"code_verifier": code_verifier} if code_verifier else {})
            )
            return token
        except Exception as e:
            logger.exception("Token exchange failed")
            raise

    def refresh_access_token(self, refresh_token):
        client = self.get_oauth_session(token={"refresh_token": refresh_token})
        try:
            return client.refresh_token(
                url=self.token_url,
                refresh_token=refresh_token,
                scope=None
            )
        except Exception as e:
            logger.exception("Token refresh failed")
            raise

    def fetch_userinfo(self, access_token):
        headers = {"Authorization": f"Bearer {access_token}"}
        try:
            resp = requests.get(self.userinfo_url, headers=headers)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.exception("Userinfo fetch failed")
            raise

    def fetch_dependent_tokens(self, access_token, grant_type, scope=None, access_type=None):
        client = self.get_oauth_session()
        try:
            token = client.fetch_token(url=self.token_url,
                                       token=access_token,
                                       scope=scope,
                                       grant_type=grant_type,
                                       access_type=access_type)
            return token
        except Exception as e:
            logger.exception("Dependent token fetch failed")
            raise

    def validate_id_token(self, id_token, nonce=None):
        self._load_jwks()
        claims = jwt.decode(
            id_token,
            key=self.jwks,
            claims_options={
                "iss": {"values": [self.issuer], "essential": True},
                "aud": {"values": [self.client_id], "essential": True},
                "exp": {"essential": True},
                "iat": {"essential": True},
                "nonce": {"value": nonce} if nonce else {"essential": False}
            }
        )
        logger.debug(f"Validating ID token claims: {claims}")
        claims.validate(leeway=120)
        return dict(claims)

    def revoke_token(self, scope: str, token: str, token_type_hint: str = "access_token") -> bool:
        """
        Revoke an access or refresh token at the provider’s revocation endpoint.
        Returns True on HTTP 200, False otherwise.
        """
        if not self.revocation_url:
            raise NotImplementedError("Revocation endpoint not configured for this client")

        # build a session that can do client_secret_basic if we have a secret
        client = self.get_oauth_session()
        try:
            resp = client.revoke_token(
                url=self.revocation_url,
                token=token,
                token_type_hint=token_type_hint,
            )
            return resp.status_code == 200
        except Exception as e:
            logger.warning(f"Token revocation failed for scope {scope} with token_type_hint={token_type_hint}: {e}")
            return False

    def introspect_token(self, token, token_type_hint="access_token", **kwargs):
        if not self.introspect_url:
            raise NotImplementedError("Introspection not configured for this client")

        # build a session that can do client_secret_basic if we have a secret
        client = self.get_oauth_session()
        try:
            resp = client.introspect_token(self.introspect_url,
                                           token=token,
                                           token_type_hint=token_type_hint,
                                           **kwargs)
            return resp.json()
        except Exception as e:
            logger.exception(f"Token introspection failed: token_type_hint={token_type_hint}")
            raise

    def validate_access_token(self, access_token, required_audience=None, **kwargs):
        """
        Validate an access token using introspection and basic metadata checks.

        Args:
            access_token (str): The access token to validate.
            required_audience (str or list[str], optional): Expected audience(s).

        Returns:
            dict: Validated claims from the token.

        Raises:
            ValueError: If the token is invalid or missing required fields.
        """
        introspect_url = self.introspect_url
        if not introspect_url:
            raise NotImplementedError("Introspection not configured for this client")

        try:
            claims = self.introspect_token(access_token, **kwargs)
        except Exception as e:
            raise ValueError(f"Token introspection failed: {e}") from e

        if not claims.get("active"):
            raise ValueError("Inactive or expired access token")

        now = time.time()
        exp = claims.get("exp")
        iat = claims.get("iat")
        nbf = claims.get("nbf", iat)

        if exp and now >= exp:
            raise ValueError("Access token expired")
        if nbf and now < nbf:
            raise ValueError("Access token not yet valid")
        if iat and now < iat:
            logger.warning("Token issued in the future — check client/server clock skew")

        # Validate audience
        aud = claims.get("aud")
        if required_audience:
            required = [required_audience] if isinstance(required_audience, str) else required_audience
            if isinstance(aud, str):
                aud = [aud]
            if not set(aud or []) & set(required):
                raise ValueError(f"Access token audience mismatch: expected {required}, got {aud}")

        # Validate issuer
        expected_iss = self.issuer
        actual_iss = claims.get("iss")
        if expected_iss and actual_iss and actual_iss.rstrip("/") != expected_iss.rstrip("/"):
            raise ValueError(f"Issuer mismatch: expected {expected_iss}, got {actual_iss}")

        logger.debug(f"Validated access token claims: {claims}")
        return dict(claims)

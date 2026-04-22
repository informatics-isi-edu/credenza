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
import time
import logging
from secrets import token_urlsafe
from urllib.parse import urlencode
from flask import Blueprint, request, redirect, current_app, abort, render_template_string

from ..telemetry import audit_event
from ..api.session.storage.session_store import CONSENT_DEFAULT_TTL

logger = logging.getLogger(__name__)

consent_blueprint = Blueprint("consent", __name__)

_CONSENT_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize Access</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: system-ui, sans-serif;
      background: #f5f5f5;
      display: flex;
      justify-content: center;
      align-items: flex-start;
      min-height: 100vh;
      margin: 0;
      padding: 40px 16px;
      color: #111;
    }
    .card {
      background: white;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      padding: 2rem;
      width: 100%;
      max-width: 480px;
    }
    .card-header { margin-bottom: 1.25rem; }
    .card-header h2 { margin: 0 0 4px; font-size: 1.25rem; }
    .card-header p { margin: 0; color: #555; font-size: 0.875rem; }
    .section {
      background: #f9f9f9;
      border: 1px solid #e5e5e5;
      border-radius: 6px;
      padding: 12px 16px;
      margin-bottom: 12px;
    }
    .section-title {
      font-size: 0.72em;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #888;
      margin: 0 0 8px 0;
    }
    ul { margin: 0; padding-left: 18px; }
    li { margin-bottom: 4px; font-size: 0.875em; line-height: 1.45; }
    li strong { color: #111; }
    li span { color: #555; }
    .service-section {
      background: #f0fdf4;
      border: 1px solid #bbf7d0;
      border-left: 3px solid #16a34a;
      border-radius: 6px;
      padding: 12px 16px;
      margin-bottom: 12px;
    }
    .service-section .section-title { color: #14532d; }
    .deleg-section {
      background: #fffbeb;
      border: 1px solid #fde68a;
      border-left: 3px solid #d97706;
      border-radius: 6px;
      padding: 12px 16px;
      margin-bottom: 12px;
    }
    .deleg-section .section-title { color: #92400e; }
    .actions {
      display: flex;
      gap: 10px;
      margin-top: 1.5rem;
    }
    .btn {
      flex: 1;
      padding: 10px 0;
      border-radius: 6px;
      font-size: 0.9em;
      font-weight: 600;
      cursor: pointer;
      border: none;
    }
    .btn-approve { background: #2563eb; color: #fff; }
    .btn-approve:hover { background: #1d4ed8; }
    .btn-deny { background: #fff; color: #333; border: 1px solid #d1d5db; }
    .btn-deny:hover { background: #f9fafb; }
  </style>
</head>
<body>
  <div class="card">
    <div class="card-header">
      <h2>{{ client_name }} is requesting access</h2>
      <p>Allow <strong>{{ client_name }}</strong> to connect to your account and access services on your behalf?</p>
    </div>

    {% if resources %}
    <div class="service-section">
      <p class="section-title">Service Access Requested</p>
      <ul>
        {% for r in resources %}
        <li>{% if labels.get(r) %}<strong>{{ labels[r] }}</strong> <span style="color:#888">({{ r }})</span>{% else %}<strong>{{ r }}</strong>{% endif %}</li>
        {% endfor %}
      </ul>
    </div>
    {% endif %}

    {% if delegation_targets %}
    <div class="deleg-section">
      <p class="section-title">Delegation notice</p>
      <p style="margin: 0 0 8px; font-size: 0.875em;">{{ client_name }} may further act as you when accessing:</p>
      <ul>
        {% for t in delegation_targets %}
        <li>{% if labels.get(t) %}<strong>{{ labels[t] }}</strong> <span style="color:#888">({{ t }})</span>{% else %}<strong>{{ t }}</strong>{% endif %}</li>
        {% endfor %}
      </ul>
    </div>
    {% endif %}

    {% if scope_list %}
    <div class="section">
      <p class="section-title">Scopes requested</p>
      <ul>
        {% for s in scope_list %}
        <li><strong>{{ s }}</strong>{% if labels.get(s) %} &mdash; <span>{{ labels[s] }}</span>{% endif %}</li>
        {% endfor %}
      </ul>
    </div>
    {% endif %}

    <form method="post" action="{{ base_url }}/authorize/consent">
      <input type="hidden" name="pending" value="{{ pending_key }}">
      <div class="actions">
        <button class="btn btn-approve" type="submit" name="action" value="approve">Allow access</button>
        <button class="btn btn-deny" type="submit" name="action" value="deny">Deny</button>
      </div>
    </form>
  </div>
</body>
</html>
"""


def is_consent_needed(store, registry, principal: str, client_id: str, resources: list) -> bool:
    """
    Return True if the consent page must be shown.
    Checks authorization consent (principal, client_id) and, when the requested
    resource maps to an RS with exchange targets, delegation consent (principal, rs_resource).
    """
    if store.get_consent_auth(principal, client_id) is None:
        return True

    if resources:
        rs_resource = resources[0]
        rs_rec = registry.find_rs_by_resource(rs_resource) if registry else None
        if rs_rec and rs_rec.allowed_token_exchange_targets:
            if store.get_consent_deleg(principal, rs_resource) is None:
                return True

    return False


@consent_blueprint.route("/authorize/consent", methods=["GET"])
def consent_page():
    pending_key = request.args.get("pending")
    if not pending_key:
        abort(400, description="Missing pending parameter")

    store = current_app.config["SESSION_STORE"]
    registry = current_app.config.get("CLIENT_REGISTRY")

    pending = store.get_pending_consent(pending_key)
    if not pending:
        abort(400, description="Consent request expired or not found")

    client_id = pending["client_id"]
    client_rec = registry.get(client_id) if registry else None

    resources = pending.get("resources", [])
    rs_resource = resources[0] if resources else None
    rs_rec = registry.find_rs_by_resource(rs_resource) if (registry and rs_resource) else None
    delegation_targets = rs_rec.allowed_token_exchange_targets if rs_rec else []

    global_labels = current_app.config.get("CONSENT_LABELS") or {}
    realm = pending.get("realm", "")
    idp_profiles = current_app.config.get("OIDC_IDP_PROFILES") or {}
    realm_labels = (idp_profiles.get(realm) or {}).get("consent_labels") or {}
    per_client_labels = client_rec.consent_labels if client_rec else {}
    labels = {**global_labels, **realm_labels, **per_client_labels}

    # Display name: consent_display_name -> desc -> client_id
    client_name = (client_rec.consent_display_name or client_rec.desc or client_id) if client_rec else client_id

    scope_list = [s for s in pending.get("scope", "").split() if s]
    if not scope_list and client_rec:
        scope_list = list(client_rec.allowed_scopes)
    base_url = current_app.config.get("BASE_URL", "")

    template_path = current_app.config.get("CONSENT_TEMPLATE_PATH")
    if template_path:
        try:
            with open(template_path, "r", encoding="utf-8") as fh:
                template_src = fh.read()
        except OSError as exc:
            logger.error("Failed to load consent template from %s: %s", template_path, exc)
            template_src = _CONSENT_TEMPLATE
    else:
        template_src = _CONSENT_TEMPLATE

    return render_template_string(
        template_src,
        pending_key=pending_key,
        client_id=client_id,
        client_name=client_name,
        scope_list=scope_list,
        resources=resources,
        delegation_targets=delegation_targets,
        labels=labels,
        base_url=base_url,
    )


@consent_blueprint.route("/authorize/consent", methods=["POST"])
def consent_submit():
    store = current_app.config["SESSION_STORE"]
    registry = current_app.config.get("CLIENT_REGISTRY")

    pending_key = request.form.get("pending")
    action = request.form.get("action")

    if not pending_key:
        abort(400, description="Missing pending parameter")

    pending = store.get_and_consume_pending_consent(pending_key)
    if not pending:
        abort(400, description="Consent request expired or not found")

    redirect_uri = pending["redirect_uri"]
    oauth_state = pending.get("oauth_state", "")

    if action != "approve":
        params = {"error": "access_denied"}
        if oauth_state:
            params["state"] = oauth_state
        audit_event("consent_denied",
                    session_id=pending.get("session_id"),
                    client_id=pending.get("client_id"),
                    sub=pending.get("sub"))
        return redirect(f"{redirect_uri}?{urlencode(params)}")

    # Approve: store consent records then issue authorization code
    principal = pending.get("principal", "")
    client_id = pending["client_id"]
    resources = pending.get("resources", [])
    consent_ttl = current_app.config.get("CONSENT_TTL", CONSENT_DEFAULT_TTL)

    store.set_consent_auth(principal, client_id, ttl=consent_ttl)

    if resources:
        rs_resource = resources[0]
        rs_rec = registry.find_rs_by_resource(rs_resource) if registry else None
        if rs_rec and rs_rec.allowed_token_exchange_targets:
            store.set_consent_deleg(principal, rs_resource, ttl=consent_ttl)

    auth_code = token_urlsafe(32)
    sid = pending["session_id"]
    realm = pending["realm"]
    code_payload = {
        "session_id":            sid,
        "client_id":             client_id,
        "redirect_uri":          redirect_uri,
        "code_challenge":        pending.get("code_challenge"),
        "code_challenge_method": pending.get("code_challenge_method"),
        "scope":                 pending.get("scope", ""),
        "resources":             resources,
        "realm":                 realm,
        "issued_at":             int(time.time()),
    }
    store.set_authorization_code(auth_code, code_payload, ttl=300)
    logger.info("OAuth authorization code issued via consent for client=%s session=%s", client_id, sid)
    audit_event("authorization_code_issued",
                session_id=sid,
                client_id=client_id,
                sub=pending.get("sub"),
                realm=realm,
                via_consent=True)

    params = {"code": auth_code}
    if oauth_state:
        params["state"] = oauth_state
    return redirect(f"{redirect_uri}?{urlencode(params)}")
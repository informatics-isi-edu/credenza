# Copyright 2026 University of Southern California
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

from flask import request, Request

def client_ip(req: Request = None) -> str:
    """
    Return the best-effort client IP for logging, audit, and rate limiting.

    IMPORTANT: Assumptions & caveats about `request.remote_addr`

    1) Direct exposure (no reverse proxy):
       - `request.remote_addr` is the real client IP. Safe to use as-is.

    2) Behind a reverse proxy (Traefik / NGINX Ingress / mod_proxy / cloud LB):
       - By default, the app sees the proxy's IP as `remote_addr`.
       - So we MUST either:
         a) enable Werkzeug ProxyFix in the app, and restrict trust to specific proxy IPs
            (gunicorn: `--forwarded-allow-ips=<comma-separated literal IPs>`), or
         b) on Apache/mod_wsgi, enable `mod_remoteip` with an explicit allowlist
            (`RemoteIPTrustedProxy`), so Apache rewrites `REMOTE_ADDR` before the app.
       - Only after (a) or (b) is correctly configured will `request.remote_addr`
         reflect the true client IP (derived from `X-Forwarded-For`).

    3) Don't trust headers alone:
       - Never trust `X-Forwarded-For` without a trust boundary. It is trivially spoofable.
       - Gunicorn's `--forwarded-allow-ips` (or Apache `RemoteIPTrustedProxy`) forms that boundary.
         If the peer is not in the allowlist, forwarded headers are ignored.

    4) Multiple proxy hops (e.g., cloud LB -> Traefik / NGINX Ingress / mod_proxy -> app):
       - Set ProxyFix hop counts accordingly (x_for/x_proto/etc. = 2) OR configure Apache `mod_remoteip`
         to trust both layers. Also include each proxy's literal IP in the allowlist.
       - If hop counts or allowlists are wrong, you'll either see the proxy IP, or you'll
         accept spoofed headers--both are bad.

    Summary:
      - Prefer to fix client-IP derivation at the edge (Apache mod_remoteip) or enable ProxyFix
        *with a strict allowlist*. After that, using `request.remote_addr` centrally here is correct.

    """
    # This relies on the app being configured correctly (ProxyFix or mod_remoteip).
    ip = "unknown"
    if not req:
        req = request
    if req:
        ip = (req.remote_addr or ip).strip()

    return ip

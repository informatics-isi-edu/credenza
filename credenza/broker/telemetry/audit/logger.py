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
import datetime
import logging
from flask import current_app

logger = logging.getLogger(__name__)

def audit_event(event, **kwargs):
    now = datetime.datetime.now().astimezone()
    log_entry = {
        "ts": now.isoformat(), # ISO 8601 timestamp with offset
        "event": event,
        **kwargs
    }

    try:
        path = os.path.abspath(current_app.config.get("AUDIT_LOG_PATH", "credenza/authn-audit.log"))
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
            f.flush()
    except Exception as e:
        logging.getLogger("audit").error(f"[audit] failed to write log entry: {e}", exc_info=True)

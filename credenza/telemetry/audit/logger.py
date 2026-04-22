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
import datetime
import logging
from logging import StreamHandler
from logging.handlers import SysLogHandler
from pythonjsonlogger import json
from flask import has_request_context, request
from ...api.common import client_ip

logger = logging.getLogger(__name__)
svc_logger = logging.getLogger("credenza")

def init_audit_logger(use_syslog=False):
    log_handler = StreamHandler()  # default: stderr

    # the use of '/dev/log' causes SysLogHandler to assume the availability of Unix sockets
    syslog_socket = "/dev/log"
    if use_syslog and (os.path.exists(syslog_socket) and os.access(syslog_socket, os.W_OK)):
        try:
            log_handler = SysLogHandler(address=syslog_socket, facility=SysLogHandler.LOG_LOCAL1)
            log_handler.ident = 'credenza-audit: '
        except Exception as e:
            # fallback to stderr
            svc_logger.warning(f"Failed to initialize syslog audit handler, falling back to stderr: {e}")

    formatter = json.JsonFormatter("{message}", style="{", rename_fields={"message": "event"})
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False  # prevent double-emit through the root handler

def audit_event(event, **kwargs):
    extra = {}

    if has_request_context():
        ip = client_ip(request)
        if ip is not None:
            extra["client_ip"] = ip

    log_entry = {
        "event": event,
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        **extra,
        **kwargs
    }
    logger.info(log_entry)

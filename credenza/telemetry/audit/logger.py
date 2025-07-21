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
from logging.handlers import SysLogHandler, TimedRotatingFileHandler
from pythonjsonlogger import json

logger = logging.getLogger(__name__)

def init_audit_logger(filename="credenza-audit.log", use_syslog=False):
    # Default logger
    log_handler = TimedRotatingFileHandler(filename=filename, when="D", interval=1, backupCount=0)

    # the use of '/dev/log' causes SysLogHandler to assume the availability of Unix sockets
    syslog_socket = "/dev/log"
    use_syslog = use_syslog and (os.path.exists(syslog_socket) and os.access(syslog_socket, os.W_OK))
    if use_syslog:
        try:
            log_handler = SysLogHandler(address=syslog_socket, facility=SysLogHandler.LOG_LOCAL1)
            log_handler.ident = 'credenza-audit: '
        except:
            # fallback to the default logger
            print(f"Failed to initialize syslog logger, falling back to {log_handler.__class__.__name__}")
            pass

    formatter = json.JsonFormatter("{message}", style="{", rename_fields={"message": "event"})
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)

def audit_event(event, **kwargs):
    log_entry = {
        "event": event,
        "timestamp": datetime.datetime.now().astimezone().isoformat(), # ISO 8601 timestamp with offset
        **kwargs
    }
    logger.info(log_entry)

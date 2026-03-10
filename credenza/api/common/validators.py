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
from typing import List, Sequence, Optional

DEFAULT_MAX_ID_LEN = 512
DEFAULT_MAX_LIST_LEN = 128
DEFAULT_MAX_TOKEN_LEN = 256

class ValidationError(ValueError):
    """Raised for validation failures in config/adapter inputs."""

def validate_non_empty(s: Optional[str], name: str) -> str:
    if not s:
        raise ValidationError(f"{name} is required")
    return s

def validate_no_whitespace(s: str, name: str) -> None:
    if isinstance(s, str):
        if any(c.isspace() for c in s):
            raise ValidationError(f"{name} must not contain whitespace")

def validate_bounded(s: str, name: str, max_len: int = DEFAULT_MAX_ID_LEN) -> None:
    if len(s) > max_len:
        raise ValidationError(f"{name} exceeds {max_len} characters")

def validate_token_list(name: str, vals: Sequence[str], *, max_len: int = DEFAULT_MAX_LIST_LEN, max_token_len: int = DEFAULT_MAX_TOKEN_LEN) -> List[str]:
    if not vals:
        raise ValidationError(f"{name} must not be empty")
    if len(vals) > max_len:
        raise ValidationError(f"{name} has too many entries")
    out: List[str] = []
    for v in vals:
        validate_non_empty(v, f"{name} entry")
        validate_no_whitespace(v, f"{name} entry")
        validate_bounded(v, f"{name} entry", max_token_len)
        out.append(v)
    return out


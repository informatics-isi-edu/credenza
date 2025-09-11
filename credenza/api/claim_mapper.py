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
import json, os, fnmatch
from typing import Any, Dict, List, Union

PathSeg = Union[str, None]
PathSpec = Union[str, List[PathSeg]]  # "groups" OR ["resource_access", None, "roles"]

def load_claim_map(path: str) -> Dict[str, List[PathSpec]]:
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _match_key(d: dict, seg: str):
    """Return the first (key, value) whose key matches seg; seg may include *."""
    if "*" in seg:
        for k, v in d.items():
            if fnmatch.fnmatch(k, seg):
                return k, v
        return None, None
    return (seg, d.get(seg)) if seg in d else (None, None)

def _resolve_one(obj: Any, path: PathSpec):
    """Resolve a single path spec against obj. Returns None if not found/non-existent."""
    # String path = single key (supports * at this level; dots are literal)
    if isinstance(path, str):
        if isinstance(obj, dict):
            _, val = _match_key(obj, path)
            return val
        return None

    # List-of-segments path (str | None only)
    cur = obj
    i = 0
    while i < len(path):
        seg = path[i]

        if seg is None:
            # wildcard over dict keys: evaluate remainder for each child, flatten list results
            if not isinstance(cur, dict):
                return None
            rem = path[i+1:]
            acc: List[Any] = []
            for v in cur.values():
                got = _resolve_one(v, rem if len(rem) > 1 else (rem[0] if rem else []))
                if got is None:
                    continue
                if isinstance(got, list):
                    acc.extend(got)
                else:
                    acc.append(got)
            return acc if acc else None

        # seg is str
        if isinstance(cur, dict):
            _, val = _match_key(cur, seg)
            if val is None:
                return None
            cur = val
            i += 1
            continue

        # encountering a list or scalar where a dict key is expected -> unsupported
        return None

    return cur

def resolve_claim(userinfo: dict, claim_map: Dict[str, List[PathSpec]], key: str, default=None):
    """Try each path for 'key' in order; return the first non-empty (not None, '', []) value."""
    paths = claim_map.get(key, [])
    for p in paths:
        val = _resolve_one(userinfo, p)
        if val not in (None, "", []):
            return val
    return default

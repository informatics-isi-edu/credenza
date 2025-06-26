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
from typing import Iterable
from credenza.api.session.storage.backends.base import StorageBackend

class ValkeyBackend(StorageBackend):
    def __init__(self, **kwargs):
        import valkey
        url = kwargs.get('url')
        self.r = valkey.Valkey.from_url(url=url)

    def setex(self, k,v,t):
        self.r.set(k,v,t)

    def get(self, k):
        return self.r.get(k)

    def delete(self, k):
        self.r.delete(k)

    def keys(self, pat):
        return self.r.keys(prefix=pat.rstrip("*"))

    def scan_iter(self, pattern: str) -> Iterable[str]:
        return self.r.scan_iter(match=pattern)

    def exists(self, key: str) -> bool:
        return self.r.exists(key)

    def ttl(self, k):
        return self.r.ttl(k)
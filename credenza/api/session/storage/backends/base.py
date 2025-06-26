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
import logging
from abc import ABC, abstractmethod
from typing import Optional, List, Union, Iterable
from werkzeug.utils import import_string
from credenza.api.session.storage.backends import STORAGE_BACKENDS

logger = logging.getLogger(__name__)


class StorageBackend(ABC):
    @abstractmethod
    def __init__(self, **kwargs): ...

    @abstractmethod
    def setex(self, key: str, value: Union[str, bytes], ttl: int) -> None: ...

    @abstractmethod
    def get(self, key: str) -> Optional[bytes]: ...

    @abstractmethod
    def delete(self, key: str) -> None: ...

    @abstractmethod
    def keys(self, pattern: str) -> List[str]: ...

    @abstractmethod
    def scan_iter(self, pattern: str) -> Iterable[str]: ...

    @abstractmethod
    def exists(self, key: str) -> bool: ...

    @abstractmethod
    def ttl(self, key: str) -> int: ...

def create_storage_backend(backend_name: str, **kwargs) -> StorageBackend:
    backend_class = STORAGE_BACKENDS[backend_name]
    logger.debug(f"Creating storage backend type '{backend_name}' with implementation '{backend_class}'")
    return import_string(backend_class)(**kwargs)

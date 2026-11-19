#
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
import threading
from credenza.api.session.storage import session_lock as sl


def _ids_on_distinct_stripes():
    first = "session-a"
    for i in range(1000):
        other = f"session-{i}"
        if sl._stripe(other) is not sl._stripe(first):
            return first, other
    raise AssertionError("no two ids on distinct stripes")


def test_lock_is_held_for_the_block_and_released_after():
    with sl.session_lock("s1") as locked:
        assert locked is True
        assert sl._stripe("s1").locked()
    assert not sl._stripe("s1").locked()


def test_non_blocking_attempt_fails_while_another_thread_holds_it():
    holding = threading.Event()
    release = threading.Event()

    def holder():
        with sl.session_lock("s1"):
            holding.set()
            release.wait(5)

    t = threading.Thread(target=holder)
    t.start()
    try:
        assert holding.wait(5)
        with sl.session_lock("s1", blocking=False) as locked:
            assert locked is False
        with sl.session_lock("s1", timeout=0.05) as locked:
            assert locked is False
    finally:
        release.set()
        t.join(5)
    with sl.session_lock("s1", blocking=False) as locked:
        assert locked is True


def test_sessions_on_different_stripes_do_not_contend():
    a, b = _ids_on_distinct_stripes()
    with sl.session_lock(a):
        with sl.session_lock(b, blocking=False) as locked:
            assert locked is True


def test_stripe_choice_is_stable():
    assert sl._stripe("abc") is sl._stripe("abc")
    assert len(sl._STRIPES) == sl.NUM_STRIPES == 256

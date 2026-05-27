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
import pytest

from credenza.api.common.validators import (
    validate_non_empty,
    validate_no_whitespace,
    validate_bounded,
    validate_token_list,
    ValidationError,
)


def test_validate_non_empty_success():
    assert validate_non_empty("abc", "name") == "abc"
    assert validate_non_empty("0", "zero") == "0"


def test_validate_non_empty_raises_on_empty_or_none():
    with pytest.raises(ValidationError) as e:
        validate_non_empty("", "foo")
    assert "foo is required" in str(e.value)

    with pytest.raises(ValidationError) as e:
        validate_non_empty(None, "bar")
    assert "bar is required" in str(e.value)


def test_validate_no_whitespace_success():
    # simple non-whitespace strings
    validate_no_whitespace("abc123", "tok")
    validate_no_whitespace("a-b_c", "tok2")


def test_validate_no_whitespace_raises_on_space_and_newline():
    with pytest.raises(ValidationError) as e:
        validate_no_whitespace("has space", "field")
    assert "field must not contain whitespace" in str(e.value)

    with pytest.raises(ValidationError):
        validate_no_whitespace("newline\nhere", "f2")


def test_validate_bounded_success_and_failure():
    # default max is large; this should pass
    validate_bounded("short", "id")

    # build a long string and assert failure
    long_s = "x" * 600
    with pytest.raises(ValidationError) as e:
        validate_bounded(long_s, "longid")
    assert "longid exceeds" in str(e.value)

    # custom max_len parameter
    validate_bounded("abcd", "c", max_len=4)
    with pytest.raises(ValidationError):
        validate_bounded("abcde", "c", max_len=4)


def test_validate_token_list_success_default_limits():
    vals = ["one", "two", "three"]
    out = validate_token_list("tokens", vals)
    assert out == vals


def test_validate_token_list_raises_on_empty_list():
    with pytest.raises(ValidationError) as e:
        validate_token_list("tokens", [])
    assert "tokens must not be empty" in str(e.value)


def test_validate_token_list_raises_on_too_many_entries():
    # use small max_len to trigger
    vals = [str(i) for i in range(6)]
    with pytest.raises(ValidationError) as e:
        validate_token_list("t", vals, max_len=5)
    assert "t has too many entries" in str(e.value)


def test_validate_token_list_raises_on_token_whitespace_and_empty_entry():
    with pytest.raises(ValidationError):
        validate_token_list("t", ["ok", "has space", "x"])

    with pytest.raises(ValidationError):
        validate_token_list("t", ["", "a"])


def test_validate_token_list_token_length_limit_and_custom_max_token_len():
    # default token max should be enforced (DEFAULT_MAX_TOKEN_LEN = 256), but test custom small limit
    vals = ["short", "ok"]
    # fine with small max_token_len
    out = validate_token_list("t", vals, max_token_len=10)
    assert out == vals

    # exceed single-token length
    long_token = "x" * 12
    with pytest.raises(ValidationError):
        validate_token_list("t", [long_token], max_token_len=10)

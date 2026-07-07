import pytest

from sentinel_worker.payload_guard import (
    MAX_METADATA_FIELD_LENGTH,
    SourcePayloadError,
    assert_no_source_markers,
)


def test_clean_metadata_passes():
    assert_no_source_markers("JWT auth middleware", field="node.label")


def test_empty_and_none_like_values_pass():
    assert_no_source_markers("", field="node.label")


def test_diff_marker_rejected():
    with pytest.raises(SourcePayloadError):
        assert_no_source_markers("+++ b/app.py\nsome content", field="node.intent")


def test_secret_marker_rejected():
    with pytest.raises(SourcePayloadError):
        assert_no_source_markers("use AKIAIOSFODNN7EXAMPLE for auth", field="node.label")


def test_oversized_field_rejected():
    with pytest.raises(SourcePayloadError):
        assert_no_source_markers("x" * (MAX_METADATA_FIELD_LENGTH + 1), field="node.intent")


def test_field_at_limit_passes():
    assert_no_source_markers("x" * MAX_METADATA_FIELD_LENGTH, field="node.intent")

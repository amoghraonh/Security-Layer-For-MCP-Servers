"""Deterministic risk scores are explainable and never authorization decisions."""

from app.security.risk import assess_tool_request


def test_read_and_destructive_operations_have_distinct_explainable_scores() -> None:
    read = assess_tool_request("read_local_repository_file", {"relative_path": "README.md"})
    deletion = assess_tool_request("delete_resource", {"resource_name": "production-database"})

    assert read.score == 10
    assert read.category == "Low"
    assert read.factors == ["read_only_operation"]
    assert deletion.score == 100
    assert deletion.category == "High"
    assert "destructive_operation" in deletion.factors
    assert "production_target_indicator" in deletion.factors

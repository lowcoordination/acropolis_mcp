from __future__ import annotations

from argus.aggregate import (
    MAX_TOOL_NAME_LENGTH,
    fits_name_limit,
    namespace_tool_definition,
    namespaced_tool_name,
    split_namespaced_tool_name,
)


def test_namespaced_tool_name():
    assert namespaced_tool_name("shell", "shell_run") == "shell__shell_run"


def test_split_namespaced_tool_name_roundtrip():
    assert split_namespaced_tool_name("shell__shell_run") == ("shell", "shell_run")


def test_split_namespaced_tool_name_no_separator_returns_none():
    assert split_namespaced_tool_name("plain_tool") is None


def test_split_namespaced_tool_name_empty_parts_returns_none():
    assert split_namespaced_tool_name("__tool") is None
    assert split_namespaced_tool_name("slug__") is None


def test_split_prefers_first_separator_for_tool_names_containing_double_underscore():
    # slugs never contain '__' (validated [a-z0-9-]+ at creation), so partition on the FIRST
    # occurrence is correct even if the tool name itself happens to contain '__'.
    assert split_namespaced_tool_name("shell__my__tool") == ("shell", "my__tool")


def test_fits_name_limit_true_for_short_names():
    assert fits_name_limit("shell", "shell_run") is True


def test_fits_name_limit_false_for_long_combination():
    long_tool = "x" * 130
    assert fits_name_limit("shell", long_tool) is False


def test_namespace_tool_definition_preserves_other_fields():
    tool = {"name": "echo", "description": "Echo it", "inputSchema": {"type": "object"}}
    result = namespace_tool_definition("test-server", tool)
    assert result["name"] == "test-server__echo"
    assert result["description"] == "Echo it"
    assert result["inputSchema"] == {"type": "object"}
    # Original dict must not be mutated.
    assert tool["name"] == "echo"


def test_namespace_tool_definition_excludes_oversized_name():
    tool = {"name": "x" * (MAX_TOOL_NAME_LENGTH + 1)}
    assert namespace_tool_definition("s", tool) is None


def test_namespace_tool_definition_excludes_invalid_chars():
    tool = {"name": "weird tool name!"}
    assert namespace_tool_definition("s", tool) is None


def test_namespace_tool_definition_excludes_empty_name():
    assert namespace_tool_definition("s", {"name": ""}) is None
    assert namespace_tool_definition("s", {}) is None

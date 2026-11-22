"""The Unreleased changelog entry describes the build-time refusals this change adds."""

from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def test_unreleased_entry_names_the_build_time_refusals():
    text = CHANGELOG.read_text(encoding="utf-8")
    assert "## Unreleased" in text
    unreleased = text.split("## Unreleased", 1)[1].split("\n## ", 1)[0]
    assert "`build_receipt` and `build_action_receipt` refuse" in unreleased

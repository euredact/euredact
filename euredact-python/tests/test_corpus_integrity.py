"""The corpus loader must not measure a different corpus than it reports.

`load_documents()` used to skip any file it could not read. Because a
`--limit` takes an *evenly spaced* sample, losing one file shifts every
document in the sample — so two runs printing the same "documents swept"
could describe different corpora. Cross-SDK parity read 0.30% on a corpus
missing two files and 0.05% on the whole one, from an identical engine, and
nothing in the output told them apart (issue rules-engine#18).

The corpus lives in iCloud Drive on macOS, where eviction leaves the directory
entry intact: `stat` reports the full size and the read returns nothing. That
is not a hypothetical failure mode; it happened twice in one session.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import sweep  # noqa: E402
from sweep import CorpusUnreadable, load_documents  # noqa: E402


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    """A miniature corpus of three readable files."""
    for i in range(3):
        (tmp_path / f"part{i}.json").write_text(json.dumps(
            [{"source_text": f"doc {i}-{n}"} for n in range(4)]))
    monkeypatch.setattr(sweep, "DATA_DIR", tmp_path)
    monkeypatch.setattr(sweep, "_training_documents", lambda **kw: [])
    return tmp_path


class TestUnreadableFilesAreNotSkipped:
    def test_a_whole_corpus_loads(self, corpus):
        assert len(load_documents()) == 12

    def test_an_evicted_file_raises(self, corpus):
        """An iCloud-evicted file reads as empty, which is not valid JSON."""
        (corpus / "part1.json").write_text("")
        with pytest.raises(CorpusUnreadable) as exc:
            load_documents()
        assert "part1.json" in str(exc.value)

    def test_a_truncated_file_raises(self, corpus):
        (corpus / "part2.json").write_text('[{"source_text": "doc')
        with pytest.raises(CorpusUnreadable):
            load_documents()

    def test_the_message_names_every_bad_file_and_how_to_fix_it(self, corpus):
        (corpus / "part0.json").write_text("")
        (corpus / "part1.json").write_text("")
        msg = str(pytest.raises(CorpusUnreadable, load_documents).value)
        assert "part0.json" in msg and "part1.json" in msg
        assert "2 corpus file(s)" in msg
        assert "dd if=" in msg, "the message should say how to restore them"

    def test_strict_false_still_allows_exploratory_use(self, corpus):
        (corpus / "part1.json").write_text("")
        assert len(load_documents(strict=False)) == 8

    def test_a_missing_corpus_is_not_an_unreadable_one(self, tmp_path, monkeypatch):
        """An absent corpus is the documented `return 77` path, not an error."""
        monkeypatch.setattr(sweep, "DATA_DIR", tmp_path / "nothing-here")
        monkeypatch.setattr(sweep, "_training_documents", lambda **kw: [])
        assert load_documents() == []


class TestSamplingDependsOnThePopulation:
    """Why skipping mattered: the sample is drawn across the whole corpus."""

    def test_losing_a_file_changes_which_documents_are_sampled(self, corpus):
        whole = load_documents(limit=6)
        (corpus / "part1.json").write_text("")
        partial = load_documents(limit=6, strict=False)
        assert whole != partial, (
            "if these were equal, skipping a file would be harmless; they are "
            "not, which is why it must raise"
        )

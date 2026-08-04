"""Tests for cross-source Knowledge Base de-duplication (knowledge/dedup.py)."""

from __future__ import annotations

import json
import sqlite3

from kiro_crew.knowledge.dedup import (
    DocRef,
    _match_reason,
    dedup_document,
    dedup_sweep,
    filename_near_match,
    normalize_filename,
    pick_winner,
)
from kiro_crew.knowledge.embedder import floats_to_bytes
from kiro_crew.knowledge.store import KnowledgeStore


def _mk_store(tmp_path) -> KnowledgeStore:
    return KnowledgeStore(str(tmp_path / "k.db"))


def _add_upload(store, name, content_hash, vec, sig="sig1",
                created_at="2026-01-01T00:00:00"):
    """Add a one-shot upload document (its own source)."""
    sid = store.add_source(name=name, source_type="local_file", uri=f"upload://{name}")
    iid = store.add_item(
        title=name, content="body", item_type="document", source_id=sid,
        content_hash=content_hash, embedding=floats_to_bytes(vec))
    store.db.execute(
        "UPDATE items SET embedding_sig = ?, created_at = ? WHERE id = ?",
        (sig, created_at, iid))
    store.db.execute("UPDATE sources SET updated_at = ? WHERE id = ?", (created_at, sid))
    store.db.commit()
    return sid, iid


def _folder_source(store, name="Projects"):
    row = store.db.execute(
        "SELECT id FROM sources WHERE source_type = 'local_folder' AND name = ?",
        (name,)).fetchone()
    if row:
        return row["id"]
    return store.add_source(name=name, source_type="local_folder", uri=f"/tmp/{name}")


def _add_folder_file(store, file_path, content_hash, vec, sig="sig1", mtime=1000.0,
                     created_at="2026-02-01T00:00:00", folder_name="Projects"):
    """Add a folder-file document (one folder_file_state row within a folder source)."""
    sid = _folder_source(store, folder_name)
    iid = store.add_item(
        title=file_path.rsplit("/", 1)[-1], content="body", item_type="document",
        source_id=sid, content_hash=content_hash, embedding=floats_to_bytes(vec))
    store.db.execute(
        "UPDATE items SET embedding_sig = ?, created_at = ? WHERE id = ?",
        (sig, created_at, iid))
    store.db.execute(
        "INSERT INTO folder_file_state "
        "(source_id, file_path, content_hash, mtime, item_ids, last_seen, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (sid, file_path, "bytehash", mtime, json.dumps([iid]), created_at, "done"))
    store.db.commit()
    return sid, iid


def _n_uploads(store):
    return store.db.execute(
        "SELECT COUNT(*) FROM sources WHERE source_type = 'local_file'").fetchone()[0]


def _upload_owns_no_items(store):
    """The upload's own copy is gone: it owns no items."""
    return store.db.execute(
        "SELECT COUNT(*) FROM items i JOIN sources s ON s.id = i.source_id "
        "WHERE s.source_type = 'local_file'").fetchone()[0] == 0


def _upload_still_holds_a_document(store):
    """...but it is a LOCATION of the surviving copy, so the document is still
    reachable from it and deleting the winner cannot destroy it."""
    return store.db.execute(
        "SELECT COUNT(*) FROM source_locations sl JOIN sources s ON s.id = sl.source_id "
        "WHERE s.source_type = 'local_file'").fetchone()[0] > 0


class TestFilenameMatch:
    def test_copy_modifiers_match(self):
        assert filename_near_match("Report.docx", "Report (1).docx")
        assert filename_near_match("Report.docx", "Report copy.docx")
        assert filename_near_match("Report.docx", "Copy of Report.docx")

    def test_close_dates_still_match(self):
        # A few days apart -- same document, a re-save / off-by-N-day revision.
        assert filename_near_match(
            "Discovery_QBR_04_14_Final.docx", "Discovery_QBR_04_21_Final.docx")
        # Same month, no day -- same instance.
        assert filename_near_match(
            "Customer 360 - Apr 2026 Update.docx", "Customer 360 - Apr 2026 Update (1).docx")
        # A few days apart across a month boundary still counts as the same doc.
        assert filename_near_match(
            "Status 2026-03-30.docx", "Status 2026-04-02.docx")
        # Underscore-delimited, a few days apart -- still the same doc.
        assert filename_near_match(
            "Weekly_Report_04_14.docx", "Weekly_Report_04_18.docx")

    def test_month_apart_dates_do_not_match(self):
        # Distinct instances of a monthly series that share an identical stem must
        # NOT collapse, even though the title is otherwise identical.
        assert not filename_near_match(
            "Customer 360 - Apr 2026 Update.docx", "Customer 360 - Dec25 Update.docx")
        assert not filename_near_match(
            "Customer 360 - Apr 2026 Update.docx", "Customer 360 - May 2026 Update.docx")
        assert not filename_near_match(
            "Weekly Report 04_14.docx", "Weekly Report 05_14.docx")
        # Underscore-delimited series must also be caught (boundary handling).
        assert not filename_near_match(
            "Status_Update_Apr_2026.docx", "Status_Update_May_2026.docx")
        assert not filename_near_match(
            "Weekly_Report_04_14.docx", "Weekly_Report_05_14.docx")

    def test_dateless_names_unaffected_by_date_gate(self):
        # No dates on either side -> the date gate never blocks a stem match.
        assert filename_near_match("Report.docx", "Report (1).docx")
        assert filename_near_match("Roadmap copy.docx", "Roadmap.docx")

    def test_distinct_names_do_not_match(self):
        assert not filename_near_match("Quarterly Sales.docx", "Engineering Roadmap.docx")

    def test_normalize_strips_extension_and_case(self):
        assert normalize_filename("My File.DOCX") == normalize_filename("my  file")


class TestPriority:
    @staticmethod
    def _doc(**kw):
        kw.setdefault("item_ids", ["x"])
        kw.setdefault("content_hash", None)
        kw.setdefault("embedding_sig", None)
        return DocRef(**kw)

    def test_persistent_beats_transient_even_if_older(self):
        folder = self._doc(source_id="f", source_type="local_folder", filename="a",
                           recency=1.0, resident_since=5.0, file_path="/a")
        upload = self._doc(source_id="u", source_type="local_file", filename="a",
                           recency=9.0, resident_since=1.0)
        winner, loser = pick_winner(folder, upload)
        assert winner.source_id == "f"
        assert loser.source_id == "u"

    def test_newest_wins_within_class(self):
        a = self._doc(source_id="a", source_type="local_file", filename="x",
                      recency=1.0, resident_since=1.0)
        b = self._doc(source_id="b", source_type="local_file", filename="x",
                      recency=2.0, resident_since=1.0)
        winner, _ = pick_winner(a, b)
        assert winner.source_id == "b"

    def test_oldest_resident_breaks_mtime_tie(self):
        a = self._doc(source_id="a", source_type="local_file", filename="x",
                      recency=1.0, resident_since=1.0)
        b = self._doc(source_id="b", source_type="local_file", filename="x",
                      recency=1.0, resident_since=5.0)
        winner, _ = pick_winner(a, b)
        assert winner.source_id == "a"

    def test_cross_format_prefers_better_recall_format(self):
        # Same doc as docx + pdf, both in folders (persistent); the pdf is NEWER.
        # The docx must still win because it extracts cleaner (better recall).
        docx = self._doc(source_id="d", source_type="local_folder",
                         filename="Report.docx", recency=1.0, resident_since=1.0,
                         file_path="/p/Report.docx")
        pdf = self._doc(source_id="p", source_type="local_folder",
                        filename="Report.pdf", recency=9.0, resident_since=1.0,
                        file_path="/q/Report.pdf")
        winner, loser = pick_winner(docx, pdf)
        assert (winner.source_id, loser.source_id) == ("d", "p")
        # order-independent
        assert pick_winner(pdf, docx)[0].source_id == "d"

    def test_same_format_winner_unchanged_by_rank_step(self):
        # Two PDFs: the rank step is skipped (same extension) and newest still wins.
        a = self._doc(source_id="a", source_type="local_folder", filename="x.pdf",
                      recency=1.0, resident_since=1.0, file_path="/a/x.pdf")
        b = self._doc(source_id="b", source_type="local_folder", filename="x.pdf",
                      recency=2.0, resident_since=1.0, file_path="/b/x.pdf")
        assert pick_winner(a, b)[0].source_id == "b"

    def test_persistence_outranks_format(self):
        # A transient docx must NOT beat a persistent pdf -- persistence is checked
        # before the format-rank step.
        upload_docx = self._doc(source_id="u", source_type="local_file",
                                filename="Report.docx", recency=9.0, resident_since=1.0)
        folder_pdf = self._doc(source_id="f", source_type="local_folder",
                               filename="Report.pdf", recency=1.0, resident_since=1.0,
                               file_path="/p/Report.pdf")
        assert pick_winner(upload_docx, folder_pdf)[0].source_id == "f"

    def test_format_rank_ordering(self):
        from kiro_crew.knowledge.dedup import _format_rank
        assert _format_rank("a.docx") > _format_rank("a.pdf")
        assert _format_rank("a.md") >= _format_rank("a.docx")
        # unknown extension and no extension both fall back to the default rank,
        # which sits above pdf so an unknown text format isn't discarded for a pdf.
        assert _format_rank("a.pdf") < _format_rank("a.weirdext")
        assert _format_rank("noext") == _format_rank("other_noext")


class TestDedupSweep:
    def test_exact_hash_collapses_upload_into_folder(self, tmp_path):
        store = _mk_store(tmp_path)
        _add_upload(store, "Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        _add_folder_file(store, "/p/Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        results = dedup_sweep(store, apply=True)
        assert len(results) == 1
        assert results[0]["reason"] == "exact"
        assert results[0]["loser"] == "Doc.docx"
        assert results[0]["winner"] == "Doc.docx"
        # The upload keeps its source row: it is now a location of the surviving
        # copy, so the document stays reachable from it.
        assert _upload_owns_no_items(store)
        assert _upload_still_holds_a_document(store)
        assert store.db.execute(
            "SELECT COUNT(*) FROM folder_file_state").fetchone()[0] == 1  # folder kept
        store.db.close()

    def test_aggregate_source_dedups_per_document_not_wholesale(self, tmp_path):
        # An aggregate source ("Artifacts", "Auto-added") holds MANY documents
        # under one sources row. Treating it as a single dedup unit hashed only
        # its first item and made the whole library the loser, so one duplicate
        # artifact cascade-deleted every artifact. The unit is now the document:
        # only the duplicate collapses, the source row and every other document
        # in it are untouched.
        store = _mk_store(tmp_path)
        art_sid = store.add_source(
            name="Artifacts", source_type="artifact", uri="artifact://all"
        )
        dupe = store.add_item(
            title="notes", content="body", item_type="document", source_id=art_sid,
            content_hash="H1", embedding=floats_to_bytes([1.0, 0.0, 0.0, 0.0]))
        keeper = store.add_item(
            title="other", content="body2", item_type="document", source_id=art_sid,
            content_hash="H2", embedding=floats_to_bytes([0.0, 1.0, 0.0, 0.0]))
        store.db.commit()
        _add_folder_file(store, "/p/notes.md", "H1", [1.0, 0.0, 0.0, 0.0])

        results = dedup_sweep(store, apply=True)

        assert len(results) == 1
        # The aggregate source row survives.
        assert store.db.execute(
            "SELECT COUNT(*) FROM sources WHERE id = ?", (art_sid,)).fetchone()[0] == 1
        remaining = {r["id"] for r in store.db.execute(
            "SELECT id FROM items WHERE source_id = ?", (art_sid,)).fetchall()}
        assert dupe not in remaining, "the duplicate document should be collapsed"
        assert keeper in remaining, "collapsing one document must not remove the others"
        store.db.close()

    def test_aggregate_document_is_marked_so_it_is_not_re_deduped(self, tmp_path):
        # Deleting an aggregate document's items is not enough: its item-state row
        # must record that it was collapsed, or the owning sync re-ingests it and
        # the sweep collapses it again on every pass.
        store = _mk_store(tmp_path)
        art_sid = store.add_source(
            name="Artifacts", source_type="artifact", uri="artifact://all")
        iid = store.add_item(
            title="notes", content="body", item_type="document", source_id=art_sid,
            content_hash="H1", embedding=floats_to_bytes([1.0, 0.0, 0.0, 0.0]))
        store.db.execute(
            "INSERT INTO artifact_item_state "
            "(source_id, slug, content_hash, item_ids, updated_at, name, status) "
            "VALUES (?, ?, ?, ?, ?, ?, 'active')",
            (art_sid, "notes", "H1", json.dumps([iid]), "2026-01-01T00:00:00", "notes"))
        store.db.commit()
        _add_folder_file(store, "/p/notes.md", "H1", [1.0, 0.0, 0.0, 0.0])

        assert len(dedup_sweep(store, apply=True)) == 1
        row = store.db.execute(
            "SELECT status, item_ids FROM artifact_item_state WHERE slug = 'notes'"
        ).fetchone()
        assert row["status"] == "deduped"
        assert row["item_ids"] == "[]"
        # And a second pass finds nothing left to do.
        assert dedup_sweep(store, apply=True) == []
        store.db.close()

    def test_a_state_table_read_failure_cannot_abort_the_sweep(self, tmp_path):
        # The losing document's items are deleted and COMMITTED before the marker
        # tables are read. An exception from those reads would abort the sweep
        # mid-collapse, leaving the audit event unwritten -- so they degrade to
        # "no marker" instead of raising.
        store = _mk_store(tmp_path)
        _add_upload(store, "Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        _add_folder_file(store, "/p/Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0])

        class _FailingStateReads:
            def __init__(self, real):
                self._real = real

            def execute(self, sql, *a, **kw):
                if "artifact_item_state" in sql or "agent_item_state" in sql:
                    raise sqlite3.OperationalError("no such table")
                return self._real.execute(sql, *a, **kw)

            def __getattr__(self, name):
                return getattr(self._real, name)

        class _StoreProxy:
            """The real store with item-state reads made to fail."""

            def __init__(self, real):
                self._real = real
                self.db = _FailingStateReads(real.db)

            def __getattr__(self, name):
                return getattr(self._real, name)

        results = dedup_sweep(_StoreProxy(store), apply=True)  # must not raise
        assert len(results) == 1
        # The collapse still happened: the loser's chunk rows are gone.
        n_upload_items = store.db.execute(
            "SELECT COUNT(*) FROM items WHERE source_id IN "
            "(SELECT id FROM sources WHERE source_type = 'local_file')").fetchone()[0]
        assert n_upload_items == 0
        # Its now-empty source row survives, because a read failure makes the
        # emptiness check answer False rather than guess. A lingering empty row is
        # the strictly safer outcome; the next sweep reaps it.
        assert _n_uploads(store) == 1
        store.db.close()

    def test_source_holding_other_documents_is_never_deleted(self, tmp_path):
        # A source is removed only once it is provably empty, so collapsing one
        # document can never take its siblings with it.
        store = _mk_store(tmp_path)
        sid = store.add_source(name="Agg", source_type="agent", uri="agent://")
        keeper = store.add_item(
            title="keep", content="keep", item_type="document", source_id=sid,
            content_hash="H2", embedding=floats_to_bytes([0.0, 1.0, 0.0, 0.0]))
        store.add_item(
            title="dupe", content="dupe", item_type="document", source_id=sid,
            content_hash="H1", embedding=floats_to_bytes([1.0, 0.0, 0.0, 0.0]))
        store.db.commit()
        _add_folder_file(store, "/p/dupe.md", "H1", [1.0, 0.0, 0.0, 0.0])

        dedup_sweep(store, apply=True)

        assert store.db.execute(
            "SELECT COUNT(*) FROM sources WHERE id = ?", (sid,)).fetchone()[0] == 1
        assert store.db.execute(
            "SELECT COUNT(*) FROM items WHERE id = ?", (keeper,)).fetchone()[0] == 1
        store.db.close()

    def test_fuzzy_collapses_near_duplicate(self, tmp_path):
        store = _mk_store(tmp_path)
        _add_upload(store, "Plan.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        # different content hash, near-identical filename, cosine ~0.98
        _add_folder_file(store, "/p/Plan.docx", "H2", [0.98, 0.0, 0.2, 0.0])
        results = dedup_sweep(store, apply=True)
        assert len(results) == 1
        assert results[0]["reason"].startswith("fuzzy")
        assert _upload_owns_no_items(store)
        assert _upload_still_holds_a_document(store)
        store.db.close()

    def test_below_threshold_keeps_both(self, tmp_path):
        store = _mk_store(tmp_path)
        # same topic/filename but only cosine ~0.71 -- the Customer-360 Apr-vs-Dec case
        _add_upload(store, "Update.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        _add_folder_file(store, "/p/Update.docx", "H2", [0.7, 0.7, 0.0, 0.0])
        results = dedup_sweep(store, apply=True)
        assert results == []
        assert _n_uploads(store) == 1
        store.db.close()

    def test_fuzzy_requires_filename_match(self, tmp_path):
        store = _mk_store(tmp_path)
        # identical embedding (cosine 1.0) but unrelated filenames -> not a duplicate
        _add_upload(store, "Apples.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        _add_folder_file(store, "/p/Oranges.docx", "H2", [1.0, 0.0, 0.0, 0.0])
        results = dedup_sweep(store, apply=True)
        assert results == []
        assert _n_uploads(store) == 1
        store.db.close()

    def test_mismatched_embedding_sig_skips_fuzzy(self, tmp_path):
        store = _mk_store(tmp_path)
        _add_upload(store, "Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0], sig="sigA")
        _add_folder_file(store, "/p/Doc.docx", "H2", [1.0, 0.0, 0.0, 0.0], sig="sigB")
        results = dedup_sweep(store, apply=True)
        assert results == []
        assert _n_uploads(store) == 1
        store.db.close()

    def test_dry_run_changes_nothing(self, tmp_path):
        store = _mk_store(tmp_path)
        _add_upload(store, "Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        _add_folder_file(store, "/p/Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        results = dedup_sweep(store, apply=False)
        assert len(results) == 1
        assert _n_uploads(store) == 1  # nothing deleted on a dry run
        store.db.close()

    def test_apply_is_idempotent(self, tmp_path):
        store = _mk_store(tmp_path)
        _add_upload(store, "Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        _add_folder_file(store, "/p/Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        dedup_sweep(store, apply=True)
        assert dedup_sweep(store, apply=True) == []
        store.db.close()

    def test_no_duplicates_is_noop(self, tmp_path):
        store = _mk_store(tmp_path)
        _add_upload(store, "Alpha.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        _add_folder_file(store, "/p/Beta.docx", "H2", [0.0, 1.0, 0.0, 0.0])
        assert dedup_sweep(store, apply=True) == []
        assert _n_uploads(store) == 1
        store.db.close()

    def test_folder_loser_marked_deduped_not_deleted(self, tmp_path):
        store = _mk_store(tmp_path)
        # Two folders hold the same file; the newer copy wins, the older is collapsed.
        _add_folder_file(store, "/a/Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0],
                         mtime=1000.0, folder_name="A")
        _add_folder_file(store, "/b/Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0],
                         mtime=2000.0, folder_name="B")
        results = dedup_sweep(store, apply=True)
        assert len(results) == 1
        # The loser folder file keeps its state row as 'deduped' (so the next scan does
        # not re-ingest the still-on-disk file), with its items cleared.
        loser = store.db.execute(
            "SELECT status, item_ids FROM folder_file_state WHERE file_path = '/a/Doc.docx'"
        ).fetchone()
        assert loser["status"] == "deduped"
        assert loser["item_ids"] == "[]"
        winner = store.db.execute(
            "SELECT status FROM folder_file_state WHERE file_path = '/b/Doc.docx'"
        ).fetchone()
        assert winner["status"] == "done"
        store.db.close()


class TestDedupDocument:
    def test_new_upload_collapses_into_existing_folder(self, tmp_path):
        store = _mk_store(tmp_path)
        _add_folder_file(store, "/p/Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        up_sid, _ = _add_upload(store, "Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        results = dedup_document(store, up_sid, apply=True)
        assert len(results) == 1
        assert results[0]["loser"] == "Doc.docx"
        # The new upload lost to the persistent folder copy, but survives as a
        # location of it rather than being destroyed.
        assert _upload_owns_no_items(store)
        assert _upload_still_holds_a_document(store)
        store.db.close()

    def test_targeted_dedup_no_match_is_noop(self, tmp_path):
        store = _mk_store(tmp_path)
        _add_folder_file(store, "/p/Other.docx", "H2", [0.0, 1.0, 0.0, 0.0])
        up_sid, _ = _add_upload(store, "Doc.docx", "H1", [1.0, 0.0, 0.0, 0.0])
        assert dedup_document(store, up_sid, apply=True) == []
        assert _n_uploads(store) == 1
        store.db.close()

    def test_aggregate_ingest_path_collapses_the_duplicate_not_the_survivor(self, tmp_path):
        # dedup_document(source_id) runs on EVERY artifact save (ingestion.py's
        # per-ingest targeted dedup). _build_doc_for builds the DocRef for one
        # document, so the pair is real and the collapse is correct.
        store = _mk_store(tmp_path)
        art_sid = store.add_source(
            name="Artifacts", source_type="artifact", uri="artifact://all"
        )
        art_item = store.add_item(
            title="notes", content="body", item_type="document", source_id=art_sid,
            content_hash="H1", embedding=floats_to_bytes([1.0, 0.0, 0.0, 0.0]))
        store.add_item(
            title="unrelated", content="other", item_type="document", source_id=art_sid,
            content_hash="H9", embedding=floats_to_bytes([0.0, 0.0, 1.0, 0.0]))
        # The per-document name comes from the item-state table, not the aggregate
        # source's name -- so the two docs compare as the same format and recency
        # decides, rather than the aggregate losing on a bare source name.
        store.db.execute(
            "INSERT INTO artifact_item_state "
            "(source_id, slug, content_hash, item_ids, updated_at, name, status) "
            "VALUES (?, ?, ?, ?, ?, ?, 'active')",
            (art_sid, "notes", "H1", json.dumps([art_item]),
             "2026-01-01T00:00:00", "notes.md"))
        store.db.commit()
        # A one-shot upload duplicating that artifact's content. The aggregate is
        # NEWER, so it wins and the transient upload is collapsed.
        _add_upload(store, "notes.md", "H1", [1.0, 0.0, 0.0, 0.0])
        store.db.execute("UPDATE sources SET updated_at = '2099-01-01T00:00:00' WHERE id = ?",
                         (art_sid,))
        store.db.commit()

        results = dedup_document(store, art_sid, content_hash="H1", apply=True)

        assert len(results) == 1
        # The transient upload was the loser and is gone; the artifact document it
        # duplicated survives, and so does the unrelated artifact alongside it.
        assert _upload_owns_no_items(store)
        assert _upload_still_holds_a_document(store)
        surviving = {r["id"] for r in store.db.execute(
            "SELECT id FROM items WHERE source_id = ?", (art_sid,)).fetchall()}
        assert art_item in surviving
        assert len(surviving) == 2
        store.db.close()


class TestOneDocumentManyLocations:
    """A collapsed duplicate is a RELATIONSHIP, not a destroyed copy."""

    def _seed(self, tmp_path):
        """Two sources holding identical content: a folder file and an upload."""
        store = _mk_store(tmp_path)
        folder = store.add_source(name="docs", source_type="local_folder",
                                  uri=str(tmp_path / "docs"))
        upload = store.add_source(name="dropped.md", source_type="local_file",
                                  uri="upload://dropped.md")
        h = "c" * 64
        fid = store.add_item(title="design.md", content="the one true body",
                             item_type="document", source_id=folder,
                             content_hash=h)
        uid = store.add_item(title="dropped.md", content="the one true body",
                             item_type="document", source_id=upload,
                             content_hash=h)
        store.add_source_location(fid, folder)
        store.add_source_location(uid, upload)
        store.db.execute(
            "INSERT INTO folder_file_state (source_id, file_path, content_hash, mtime, "
            "item_ids, last_seen, status) VALUES (?, ?, ?, ?, ?, ?, 'done')",
            (folder, str(tmp_path / "docs" / "design.md"), h, 1000.0,
             json.dumps([fid]), "2024-01-01T00:00:00"))
        store.db.commit()
        return store, folder, upload, fid, uid

    def test_collapse_attaches_the_loser_source_to_the_winner_items(self, tmp_path):
        store, folder, upload, fid, uid = self._seed(tmp_path)
        try:
            actions = dedup_sweep(store, apply=True)
            assert actions, "expected a collapse"
            # The folder is persistent so it wins; the upload's item is gone.
            assert store.get_item(fid) is not None
            assert store.get_item(uid) is None
            # ...but the upload is now a LOCATION of the surviving item.
            holders = set(store.sources_holding_item(fid))
            assert holders == {folder, upload}, holders
        finally:
            store.db.close()

    def test_document_survives_deleting_the_source_that_won(self, tmp_path):
        """The property A exists for: deleting the winner must not lose the document."""
        store, folder, upload, fid, uid = self._seed(tmp_path)
        try:
            dedup_sweep(store, apply=True)
            store.delete_source_cascade(folder)
            item = store.get_item(fid)
            assert item is not None, "the document was destroyed with its winning source"
            assert item["content"] == "the one true body"
            # Ownership moved to the source that still holds it.
            assert item["source_id"] == upload
            assert store.sources_holding_item(fid) == [upload]
        finally:
            store.db.close()

    def test_deleting_the_winner_revives_the_loser_state_row(self, tmp_path):
        store, folder, upload, fid, uid = self._seed(tmp_path)
        try:
            dedup_sweep(store, apply=True)
            # Seed the mirror case: a folder file that LOST, so it owns nothing and
            # defers to the upload. Its own item is gone, which is what makes the
            # marker a strand risk -- nothing else would bring the file back.
            store.delete_items_batch([fid])
            store.db.execute(
                "UPDATE folder_file_state SET status='deduped', item_ids='[]', "
                "merged_into_source_id=? WHERE source_id=?", (upload, folder))
            store.db.commit()
            store.delete_source_cascade(upload)
            row = store.db.execute(
                "SELECT status, merged_into_source_id FROM folder_file_state "
                "WHERE source_id = ?", (folder,)).fetchone()
            assert row["merged_into_source_id"] is None
            # The folder owns no copy, so the file must be re-scanned rather than
            # adopting something that is not there.
            assert row["status"] == "pending", "a revived file must be re-scanned"
        finally:
            store.db.close()

    def test_two_refs_to_one_item_set_are_never_collapsed(self, tmp_path):
        """The self-annihilation guard: overlapping item_ids is not a duplicate pair."""
        store = _mk_store(tmp_path)
        try:
            sid = store.add_source(name="S", source_type="local_file", uri="upload://s")
            iid = store.add_item(title="a", content="body", item_type="document",
                                 source_id=sid, content_hash="d" * 64)
            a = DocRef(source_id="srcA", source_type="local_folder", filename="a.md",
                       item_ids=[iid], content_hash="d" * 64, embedding_sig=None,
                       recency=1.0, resident_since=1.0, file_path="/x/a.md")
            b = DocRef(source_id="srcB", source_type="local_file", filename="a.md",
                       item_ids=[iid], content_hash="d" * 64, embedding_sig=None,
                       recency=2.0, resident_since=2.0, file_path=None)
            assert a.key != b.key, "precondition: the key test must NOT be what saves us"
            assert _match_reason(store, a, b, 0.95) is None
        finally:
            store.db.close()

    def test_revived_row_adopts_a_document_reassigned_into_its_source(self, tmp_path):
        """Reviving must not re-ingest a document the source now owns.

        Deleting the winner reassigns the surviving copy to a source that still holds
        it -- possibly the very source whose row deferred to the winner. Clearing the
        marker to 'pending' there would re-ingest a document already present and leave
        that source holding two copies, so the row adopts the reassigned items instead.
        """
        store = _mk_store(tmp_path)
        try:
            folder = store.add_source(name="docs", source_type="local_folder",
                                      uri=str(tmp_path / "docs"))
            upload = store.add_source(name="drop.md", source_type="local_file",
                                      uri="upload://drop.md")
            h = "e" * 64
            uid = store.add_item(title="drop.md", content="body",
                                 item_type="document", source_id=upload,
                                 content_hash=h)
            # Post-collapse: the upload's item is also a location of the folder, and
            # the folder's row defers to the upload.
            store.add_source_location(uid, upload)
            store.add_source_location(uid, folder)
            store.db.execute(
                "INSERT INTO folder_file_state (source_id, file_path, content_hash, "
                "mtime, item_ids, last_seen, status, merged_into_source_id) "
                "VALUES (?, ?, ?, ?, '[]', '2024-01-01', 'deduped', ?)",
                (folder, str(tmp_path / "docs" / "drop.md"), h, 1000.0, upload))
            store.db.commit()

            store.delete_source_cascade(upload)

            item = store.get_item(uid)
            assert item is not None and item["source_id"] == folder
            row = store.db.execute(
                "SELECT status, item_ids, merged_into_source_id FROM folder_file_state "
                "WHERE source_id = ?", (folder,)).fetchone()
            assert row["merged_into_source_id"] is None
            assert row["status"] == "done", "a source that owns the document must not re-ingest"
            assert uid in json.loads(row["item_ids"])
        finally:
            store.db.close()

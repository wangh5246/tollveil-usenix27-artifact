#!/usr/bin/env python3
"""Automated verification gate for TollVeil v15 USENIX Security 2027 manuscript (Gate G7)."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import fitz  # PyMuPDF

WORK = Path(__file__).resolve().parents[1]


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def strip_comments_and_envs(tex: str) -> str:
    lines = []
    for line in tex.splitlines():
        # Strip unescaped % comments
        m = re.search(r"(?<!\\)%", line)
        if m:
            line = line[: m.start()]
        lines.append(line)
    text = "\n".join(lines)
    # Remove \url{...} and \href{...} and \label{...} and \ref{...} and \cite{...} and \includegraphics{...}
    text = re.sub(r"\\(?:url|href|label|ref|eqref|cite|citep|citet|includegraphics|input|bibliography|bibliographystyle)\{[^}]*\}", " ", text)
    return text


def render_pages_180dpi(pdf_path: Path, render_dir: Path) -> list[dict]:
    render_dir.mkdir(parents=True, exist_ok=True)
    doc = fitz.open(pdf_path)
    pages_info = []
    refs_page = None
    app_page = None
    for idx, page in enumerate(doc, start=1):
        txt = page.get_text("text")
        if refs_page is None and re.search(r"(?m)^\s*References\s*$", txt):
            refs_page = idx
        if app_page is None and re.search(r"(?m)^\s*A\s+Open Science\b", txt):
            app_page = idx
        pix = page.get_pixmap(dpi=180)
        out_png = render_dir / f"page_{idx:02d}.png"
        pix.save(str(out_png))
        pages_info.append({
            "page": idx,
            "width_pt": round(page.rect.width, 1),
            "height_pt": round(page.rect.height, 1),
            "png": str(out_png),
            "has_qq": "??" in txt,
        })
    doc.close()
    return pages_info, refs_page, app_page


def verify_manuscript(source_dir: Path, build_dir: Path, pdf_path: Path, render_dir: Path, receipt_path: Path) -> dict:
    log_path = build_dir / "main.log"
    bbl_path = build_dir / "main.bbl"
    aux_path = build_dir / "main.aux"

    log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    overfull_hits = re.findall(r"Overfull \\[hv]box[^\n]*", log_text)
    undef_ref_hits = re.findall(r"LaTeX Warning: Reference `[^']+' on page \d+ undefined", log_text)
    undef_cite_hits = re.findall(r"LaTeX Warning: Citation `[^']+' on page \d+ undefined", log_text)
    latex_errors = re.findall(r"(?m)^! .*$", log_text)

    # Scan all .tex files under source_dir
    tex_files = sorted(source_dir.rglob("*.tex"))
    we_us_hits = []
    version_hits = []
    identity_hits = []
    nyc_hits = []
    todo_hits = []

    forbidden_id_pat = re.compile(r"(anonymous|anonymous|/[U]sers/|/[V]olumes/|workspace|tollveil-repo)", re.I)
    we_us_pat = re.compile(r"\b(we|us|we're|we've|we'll|we'd|ourselves)\b", re.I)
    ver_pat = re.compile(r"\b[vV]\d+(?:[-_]?[rR]?\d+)?\b")
    todo_pat = re.compile(r"\b(TODO|FIXME|TBD)\b", re.I)
    nyc_pat = re.compile(r"\b(NYC|NYCTLC|New York City)\b|\$0\.75", re.I)

    for tf in tex_files:
        rel = str(tf.relative_to(source_dir))
        raw = tf.read_text(encoding="utf-8")
        cleaned = strip_comments_and_envs(raw)
        # Exclude facts.tex from prose checks (only check identity/todo)
        if forbidden_id_pat.search(raw):
            identity_hits.append({"file": rel, "matches": forbidden_id_pat.findall(raw)})
        if todo_pat.search(cleaned):
            todo_hits.append({"file": rel, "matches": todo_pat.findall(cleaned)})
        if nyc_pat.search(cleaned):
            nyc_hits.append({"file": rel, "matches": nyc_pat.findall(cleaned)})
        if rel != "facts.tex":
            m_we = we_us_pat.findall(cleaned)
            if m_we:
                we_us_hits.append({"file": rel, "matches": m_we})
            # Filter out harmless V2X or 3GPP version tokens if any
            m_ver = [v for v in ver_pat.findall(cleaned) if v not in ("V2X", "V15")]
            if m_ver:
                version_hits.append({"file": rel, "matches": m_ver})

    # Count cited references from .bbl
    bbl_text = bbl_path.read_text(encoding="utf-8", errors="replace") if bbl_path.exists() else ""
    bibitem_keys = re.findall(r"\\bibitem\{([^}]+)\}", bbl_text)

    # Render PDF & inspect page counts
    pages_info, refs_page, app_page = render_pages_180dpi(pdf_path, render_dir)
    total_pages = len(pages_info)
    main_body_pages = (refs_page - 1) if refs_page else total_pages
    qq_pages = [p["page"] for p in pages_info if p["has_qq"]]

    # Verify facts.tex macros match expected_facts.json generated from receipts
    expected_facts_path = source_dir.parent / "expected_facts.json"
    if not expected_facts_path.exists():
        expected_facts_path = WORK / "manuscript/v15/expected_facts.json"
    facts_tex_path = source_dir / "facts.tex"
    facts_mismatches = []
    facts_checked = 0
    if expected_facts_path.exists() and facts_tex_path.exists():
        expected_map = json.loads(expected_facts_path.read_text(encoding="utf-8"))
        facts_raw = facts_tex_path.read_text(encoding="utf-8")
        actual_map = dict(re.findall(r"\\newcommand\{\\([A-Za-z]+)\}\{([^}]*)\}", facts_raw))
        for k, v in expected_map.items():
            facts_checked += 1
            if actual_map.get(k) != str(v):
                facts_mismatches.append({"macro": k, "expected": str(v), "actual": actual_map.get(k)})

    checks = {
        "zero_latex_errors": len(latex_errors) == 0,
        "zero_overfull": len(overfull_hits) == 0,
        "zero_undefined_refs_or_cites": len(undef_ref_hits) == 0 and len(undef_cite_hits) == 0 and len(qq_pages) == 0,
        "main_body_le_13_pages": main_body_pages <= 13 and refs_page is not None and refs_page <= 14,
        "total_pages_le_20": total_pages <= 20,
        "cited_refs_40_to_45": 40 <= len(bibitem_keys) <= 45,
        "zero_we_us": len(we_us_hits) == 0,
        "zero_version_tags": len(version_hits) == 0,
        "zero_identity_leaks": len(identity_hits) == 0,
        "zero_nyc_legacy": len(nyc_hits) == 0,
        "zero_todos": len(todo_hits) == 0,
        "facts_100pct_matched": facts_checked > 0 and len(facts_mismatches) == 0,
        "rendered_180dpi_all_pages": len(pages_info) == total_pages and total_pages > 0,
    }
    all_pass = all(checks.values())
    result = {
        "schema": "tollveil.v15.manuscript_verify.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if all_pass else "FAIL",
        "pdf_path": str(pdf_path),
        "pdf_sha256": sha256_file(pdf_path),
        "total_pages": total_pages,
        "main_body_end_page": main_body_pages,
        "references_start_page": refs_page,
        "appendix_start_page": app_page,
        "cited_references_count": len(bibitem_keys),
        "facts_macros_checked": facts_checked,
        "facts_mismatches": facts_mismatches,
        "overfull_hits": overfull_hits,
        "undef_ref_hits": undef_ref_hits,
        "undef_cite_hits": undef_cite_hits,
        "qq_pages": qq_pages,
        "we_us_hits": we_us_hits,
        "version_hits": version_hits,
        "identity_hits": identity_hits,
        "nyc_hits": nyc_hits,
        "todo_hits": todo_hits,
        "checks": checks,
        "render_dir": str(render_dir),
    }
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "total_pages": total_pages,
        "main_body_end_page": main_body_pages,
        "references_start_page": refs_page,
        "cited_references_count": len(bibitem_keys),
        "facts_macros_checked": facts_checked,
        "checks": checks,
        "overfull_count": len(overfull_hits),
        "we_us_hits": we_us_hits,
        "version_hits": version_hits,
    }, indent=2))
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--build", type=Path, required=True)
    ap.add_argument("--pdf", type=Path, required=True)
    ap.add_argument("--renders", type=Path, required=True)
    ap.add_argument("--receipt", type=Path, required=True)
    args = ap.parse_args()
    res = verify_manuscript(args.source, args.build, args.pdf, args.renders, args.receipt)
    return 0 if res["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

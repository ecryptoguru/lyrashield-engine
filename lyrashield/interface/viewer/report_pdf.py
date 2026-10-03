"""Build and encrypt LyraShield's local PDF report.

The pinned upstream renderer supplies the shared layout and encryption helpers;
this module owns the product cover, artifact reads, and filename.
"""

from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING, Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from lyrashield.interface.viewer.transcript import (
    primary_target,
    read_run_summary,
    read_vulnerabilities,
    severity_counts,
)
from strix.interface.viewer import report_pdf as _layout


if TYPE_CHECKING:
    from pathlib import Path

    from reportlab.lib.styles import ParagraphStyle

_BORDER = _layout._BORDER
_INK = _layout._INK
_PAGE_W = A4[0]
_LogoMark = _layout._LogoMark
_esc = _layout._esc
_fmt_time = _layout._fmt_time
_duration = _layout._duration
_inline_md = _layout._inline_md
_normalize_severity = _layout._normalize_severity
_styles = _layout._styles
_section = _layout._section
_overview_flowables = _layout._overview_flowables
_finding_flowables = _layout._finding_flowables
_strip_code_fence = _layout._strip_code_fence


# Preserve the product canvas behavior while sharing the page numbering logic.
class _NumberedCanvas(_layout._NumberedCanvas):
    def showPage(self) -> None:  # noqa: N802 - reportlab API
        self._saved_states.append(dict(self.__dict__))
        start_page = getattr(self, "_startPage", None)
        if start_page is None:
            msg = "reportlab Canvas no longer exposes _startPage"
            raise AttributeError(msg)
        start_page()


def _cover(
    styles: dict[str, ParagraphStyle], record: dict[str, Any], run_name: str
) -> list[Flowable]:
    header = Table(
        [[_LogoMark(30), Paragraph("LyraShield", styles["wordmark"])]],
        colWidths=[38, _PAGE_W - 40 * mm - 38],
    )
    header.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )

    target = primary_target(record) or "Target"
    meta_rows = [
        ("TARGET", primary_target(record) or "unknown target"),
        ("RUN", run_name),
        ("SCAN MODE", str(record.get("scan_mode") or "n/a")),
        ("STATUS", str(record.get("status") or "n/a")),
        ("STARTED", _fmt_time(record.get("start_time"))),
        ("COMPLETED", _fmt_time(record.get("end_time"))),
        ("DURATION", _duration(record.get("start_time"), record.get("end_time"))),
    ]
    meta_table = Table(
        [
            [Paragraph(label, styles["meta_label"]), Paragraph(_esc(value), styles["meta_value"])]
            for label, value in meta_rows
        ],
        colWidths=[38 * mm, _PAGE_W - 40 * mm - 38 * mm],
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (0, 0), (-1, -2), 0.5, _BORDER),
            ]
        )
    )

    confidential = Table([[Paragraph("CONFIDENTIAL", styles["confidential"])]], colWidths=[120])
    confidential.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _INK),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    confidential.hAlign = "CENTER"

    return [
        header,
        Spacer(1, 150),
        Paragraph("PENETRATION TEST REPORT", styles["badge_label"]),
        Spacer(1, 20),
        Paragraph("Security Assessment", styles["cover_title"]),
        Paragraph(_esc(target), styles["cover_org"]),
        Spacer(1, 28),
        meta_table,
        Spacer(1, 90),
        confidential,
        PageBreak(),
    ]


def generate_report_pdf(run_dir: Path) -> bytes:
    """Render a branded, full-detail PDF report for the run at ``run_dir``."""
    record = read_run_summary(run_dir)
    vulns = [v for v in read_vulnerabilities(run_dir) if isinstance(v, dict)]
    counts = severity_counts(vulns)
    run_name = str(record.get("run_name") or run_dir.name)

    styles = _styles()
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title="LyraShield Security Report",
        author="LyraShield",
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=22 * mm,
        bottomMargin=24 * mm,
    )

    story: list[Flowable] = []
    story.extend(_cover(styles, record, run_name))
    story.extend(_overview_flowables(styles, record, len(vulns), counts))

    story.append(PageBreak())
    story.append(_section(styles, "Findings"))
    story.append(Spacer(1, 16))
    if vulns:
        for index, vuln in enumerate(vulns, start=1):
            story.extend(_finding_flowables(styles, index, vuln))
    else:
        story.append(Paragraph("No findings were recorded for this run.", styles["body"]))

    doc.build(story, canvasmaker=_NumberedCanvas)
    return buffer.getvalue()


generate_password = _layout.generate_password
encrypt_pdf = _layout.encrypt_pdf


def build_encrypted_report(run_dir: Path) -> tuple[bytes, str, str]:
    """Build, encrypt, and name the report. Returns (pdf_bytes, password, filename)."""
    record = read_run_summary(run_dir)
    run_name = str(record.get("run_name") or run_dir.name)
    pdf_bytes = generate_report_pdf(run_dir)
    password = generate_password()
    encrypted = encrypt_pdf(pdf_bytes, password)
    filename = f"lyrashield-report-{run_name}.pdf"
    return encrypted, password, filename


__all__ = [
    "build_encrypted_report",
    "encrypt_pdf",
    "generate_password",
    "generate_report_pdf",
]

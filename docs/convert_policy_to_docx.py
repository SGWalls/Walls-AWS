import os
import re
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement



def set_cell_bg(cell, hex_color):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcPr.append(shd)


def add_run_with_inline(para, text):
    """Add a paragraph run handling **bold** and `code` inline formatting."""
    pattern = re.compile(r"(\*\*(.+?)\*\*|`([^`]+)`)")
    last = 0
    for m in pattern.finditer(text):
        if m.start() > last:
            para.add_run(text[last:m.start()])
        if m.group(2):
            para.add_run(m.group(2)).bold = True
        elif m.group(3):
            run = para.add_run(m.group(3))
            run.font.name = "Courier New"
            run.font.size = Pt(9)
        last = m.end()
    if last < len(text):
        para.add_run(text[last:])


def parse_table(doc, lines, idx):
    """Parse a markdown table starting at idx, return next idx."""
    rows = []
    while idx < len(lines):
        line = lines[idx].strip()
        if not line.startswith("|"):
            break
        if re.match(r"^\|[-| :]+\|$", line):
            idx += 1
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        rows.append(cells)
        idx += 1

    if not rows:
        return idx

    col_count = max(len(r) for r in rows)
    table = doc.add_table(rows=len(rows), cols=col_count)
    table.style = "Table Grid"

    for r_idx, row in enumerate(rows):
        for c_idx, cell_text in enumerate(row):
            if c_idx >= col_count:
                break
            cell = table.cell(r_idx, c_idx)
            cell.text = ""
            para = cell.paragraphs[0]
            para.alignment = WD_ALIGN_PARAGRAPH.LEFT
            add_run_with_inline(para, cell_text)
            for run in para.runs:
                run.font.size = Pt(9)
            if r_idx == 0:
                set_cell_bg(cell, "1F3864")
                for run in para.runs:
                    run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                    run.bold = True
            elif r_idx % 2 == 0:
                set_cell_bg(cell, "DCE6F1")

    doc.add_paragraph()
    return idx


def convert(md_path, docx_path):
    with open(md_path, encoding="utf-8") as f:
        lines = f.readlines()

    doc = Document()

    # Page margins
    for section in doc.sections:
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)

    # Default body font
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)

    in_code_block = False
    code_lines = []
    idx = 0

    while idx < len(lines):
        raw = lines[idx].rstrip("\n")
        stripped = raw.strip()

        # Code block toggle
        if stripped.startswith("```"):
            if not in_code_block:
                in_code_block = True
                code_lines = []
                idx += 1
                continue
            else:
                para = doc.add_paragraph()
                para.style = doc.styles["Normal"]
                run = para.add_run("\n".join(code_lines))
                run.font.name = "Courier New"
                run.font.size = Pt(8)
                in_code_block = False
                code_lines = []
                idx += 1
                continue

        if in_code_block:
            code_lines.append(raw)
            idx += 1
            continue

        # Headings
        h_match = re.match(r"^(#{1,4})\s+(.*)", stripped)
        if h_match:
            level = len(h_match.group(1))
            text = h_match.group(2)
            heading_map = {1: "Heading 1", 2: "Heading 2", 3: "Heading 3", 4: "Heading 4"}
            para = doc.add_paragraph(style=heading_map.get(level, "Heading 4"))
            add_run_with_inline(para, text)
            idx += 1
            continue

        # Horizontal rule
        if re.match(r"^---+$", stripped):
            idx += 1
            continue

        # Table
        if stripped.startswith("|"):
            idx = parse_table(doc, lines, idx)
            continue

        # Blockquote
        if stripped.startswith(">"):
            text = re.sub(r"^>\s?", "", stripped)
            para = doc.add_paragraph(style="Normal")
            para.paragraph_format.left_indent = Inches(0.4)
            run = para.add_run(text)
            run.italic = True
            run.font.color.rgb = RGBColor(0x40, 0x40, 0x40)
            idx += 1
            continue

        # Bullet points
        if re.match(r"^[-*]\s+", stripped):
            text = re.sub(r"^[-*]\s+", "", stripped)
            para = doc.add_paragraph(style="List Bullet")
            add_run_with_inline(para, text)
            idx += 1
            continue

        # Numbered list
        if re.match(r"^\d+\.\s+", stripped):
            text = re.sub(r"^\d+\.\s+", "", stripped)
            para = doc.add_paragraph(style="List Number")
            add_run_with_inline(para, text)
            idx += 1
            continue

        # Bold metadata lines (e.g. **Version:** 1.0)
        if stripped.startswith("**") and ":**" in stripped:
            para = doc.add_paragraph(style="Normal")
            add_run_with_inline(para, stripped)
            idx += 1
            continue

        # Empty line
        if not stripped:
            idx += 1
            continue

        # Normal paragraph
        para = doc.add_paragraph(style="Normal")
        add_run_with_inline(para, stripped)
        idx += 1

    doc.save(docx_path)
    print(f"Saved: {docx_path}")


if __name__ == "__main__":
    md_path = input("Enter the source markdown file path: ").strip()
    docx_path = os.path.splitext(md_path)[0] + ".docx"
    convert(md_path, docx_path)

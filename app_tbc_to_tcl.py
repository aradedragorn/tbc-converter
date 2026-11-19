#!/usr/bin/env python3
"""
Surpac Macro Converter: TBC -> TCL (Streamlit Dashboard)
Created by: Michael Aragorn Purba
Run locally: streamlit run app_tbc_to_tcl.py
"""

import io
import re
import struct
import zipfile
from pathlib import Path

import streamlit as st

# ==============================================================================
# 1. TCLPRO ASCII85 DECODER
# ==============================================================================
TCLPRO_A85_MAP = {
    "v": 1,
    "w": 3,
    "x": 58,
    "y": 59,
    "|": 60,
}


def decode_tclpro_a85(encoded: str, expected_len: int = -1) -> bytes:
    """Decode TclPro's custom little-endian Ascii85 string into raw bytes."""
    out = bytearray()
    group = []

    for ch in encoded:
        if ch.isspace():
            continue
        if ch == "z" and not group:
            out.extend(b"\x00\x00\x00\x00")
            continue

        if ch in TCLPRO_A85_MAP:
            val = TCLPRO_A85_MAP[ch]
        else:
            val = ord(ch) - 33
            if not (0 <= val < 85):
                continue

        group.append(val)
        if len(group) == 5:
            num = (
                group[0]
                + group[1] * 85
                + group[2] * (85**2)
                + group[3] * (85**3)
                + group[4] * (85**4)
            )
            num &= 0xFFFFFFFF
            out.extend(num.to_bytes(4, "little", signed=False))
            group.clear()

    if len(group) >= 2:
        num = 0
        for idx, digit in enumerate(group):
            num += digit * (85**idx)
        rem_bytes = len(group) - 1
        mask = (1 << (rem_bytes * 8)) - 1
        out.extend((num & mask).to_bytes(rem_bytes, "little", signed=False))

    if expected_len >= 0:
        return bytes(out[:expected_len])
    return bytes(out)


def expected_a85_chars(byte_len: int) -> int:
    """Calculate exact number of TclPro A85 characters for a given byte length."""
    full_blocks, rem = divmod(byte_len, 4)
    return full_blocks * 5 + (rem + 1 if rem else 0)


def read_a85_block(lines: list, start_idx: int, byte_len: int) -> tuple:
    """Read lines until target A85 character count for byte_len is reached."""
    if byte_len <= 0:
        idx = start_idx + (1 if start_idx < len(lines) and lines[start_idx].strip() == "" else 0)
        return b"", idx

    target_chars = expected_a85_chars(byte_len)
    chunks = []
    collected = 0
    idx = start_idx
    while idx < len(lines) and collected < target_chars:
        chunk = lines[idx].strip()
        chunks.append(chunk)
        collected += len(chunk) + chunk.count("z") * 4
        idx += 1

    decoded = decode_tclpro_a85("".join(chunks), expected_len=byte_len)
    return decoded, idx


# ==============================================================================
# 2. TCL 8.3 BYTECODE DISASSEMBLER & DECOMPILER
# ==============================================================================
class TclExpr:
    """Represents a reconstructed Tcl expression/token on the VM evaluation stack."""

    def __init__(self, kind: str, value: str, parts=None):
        self.kind = kind  # 'lit' | 'var' | 'cmd' | 'concat'
        self.value = value
        self.parts = parts or []

    def as_word(self) -> str:
        if self.kind == "cmd":
            return f"[{self.value}]"
        if self.kind == "var":
            return f"${self.value}" if re.match(r"^[A-Za-z0-9_]+$", self.value) else f"${{{self.value}}}"
        if self.kind == "concat":
            buf = ['"']
            for p in self.parts:
                if p.kind == "var":
                    buf.append(
                        f"${p.value}" if re.match(r"^[A-Za-z0-9_]+$", p.value) else f"${{{p.value}}}"
                    )
                elif p.kind == "cmd":
                    buf.append(f"[{p.value}]")
                else:
                    buf.append(_escape_tcl_double_quoted(p.value))
            buf.append('"')
            return "".join(buf)

        s = self.value
        if s == "":
            return '""'
        if "\n" in s or re.search(r"\bfrm\d{5}\s*=", s):
            return f"{{{s}}}"
        if re.match(r"^[A-Za-z0-9_./:%+-]+$", s):
            return s
        return f'"{_escape_tcl_double_quoted(s)}"'


def _escape_tcl_double_quoted(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("[", "\\[")
        .replace("]", "\\]")
    )


TCL83_OPCODES = {
    0x00: ("DONE", ""),
    0x01: ("PUSH1", "B"),
    0x02: ("PUSH4", "I"),
    0x03: ("POP", ""),
    0x04: ("DUP", ""),
    0x05: ("CONCAT1", "B"),
    0x06: ("INVOKE_STK1", "B"),
    0x07: ("INVOKE_STK4", "I"),
    0x08: ("EVAL_STK", ""),
    0x09: ("EXPR_STK", ""),
    0x0A: ("LOAD_SCALAR1", "B"),
    0x0B: ("LOAD_SCALAR4", "I"),
    0x0C: ("LOAD_SCALAR_STK", ""),
    0x0D: ("LOAD_ARRAY1", "B"),
    0x0E: ("LOAD_ARRAY4", "I"),
    0x0F: ("LOAD_ARRAY_STK", ""),
    0x10: ("LOAD_STK", ""),
    0x11: ("STORE_SCALAR1", "B"),
    0x12: ("STORE_SCALAR4", "I"),
    0x13: ("STORE_SCALAR_STK", ""),
    0x14: ("STORE_ARRAY1", "B"),
    0x15: ("STORE_ARRAY4", "I"),
    0x16: ("STORE_ARRAY_STK", ""),
    0x17: ("STORE_STK", ""),
    0x18: ("INCR_SCALAR1", "Bb"),
    0x19: ("INCR_SCALAR_STK", "b"),
    0x1A: ("INCR_STK", ""),
    0x1B: ("INCR_ARRAY1", "Bb"),
    0x1C: ("INCR_ARRAY_STK", "b"),
    0x1D: ("INCR_SCALAR1_IMM", "Bb"),
    0x1E: ("INCR_SCALAR_STK_IMM", "b"),
    0x1F: ("INCR_ARRAY1_IMM", "Bb"),
    0x20: ("INCR_ARRAY_STK_IMM", "b"),
    0x21: ("JUMP1", "b"),
    0x22: ("JUMP4", "i"),
    0x23: ("JUMP_TRUE1", "b"),
    0x24: ("JUMP_TRUE4", "i"),
    0x25: ("JUMP_FALSE1", "b"),
    0x26: ("JUMP_FALSE4", "i"),
    0x27: ("LOR", ""),
    0x28: ("LAND", ""),
    0x29: ("BITOR", ""),
    0x2A: ("BITXOR", ""),
    0x2B: ("BITAND", ""),
    0x2C: ("EQ", ""),
    0x2D: ("NEQ", ""),
    0x2E: ("LT", ""),
    0x2F: ("GT", ""),
    0x30: ("LE", ""),
    0x31: ("GE", ""),
    0x32: ("LSHIFT", ""),
    0x33: ("RSHIFT", ""),
    0x34: ("ADD", ""),
    0x35: ("SUB", ""),
    0x36: ("MULT", ""),
    0x37: ("DIV", ""),
    0x38: ("MOD", ""),
    0x39: ("UPLUS", ""),
    0x3A: ("UMINUS", ""),
    0x3B: ("BITNOT", ""),
    0x3C: ("LNOT", ""),
    0x3D: ("CALL_BUILTIN_FUNC1", "B"),
    0x3E: ("CALL_FUNC1", "B"),
    0x3F: ("TRY_CVT_TO_NUMERIC", ""),
    0x40: ("BREAK", ""),
    0x41: ("CONTINUE", ""),
    0x42: ("FOREACH_START4", "I"),
    0x43: ("FOREACH_STEP4", "I"),
    0x44: ("BEGIN_CATCH4", "I"),
    0x45: ("END_CATCH", ""),
    0x46: ("PUSH_RESULT", ""),
    0x47: ("PUSH_RETURN_CODE", ""),
}


def disassemble_bytecode(code: bytes, literals: list) -> list:
    """Disassemble Tcl 8.3 bytecode into readable instruction dictionaries."""
    pc = 0
    n = len(code)
    insns = []
    lit_vals = [x["value"] for x in literals]

    while pc < n:
        op = code[pc]
        name, fmt = TCL83_OPCODES.get(op, (f"UNKNOWN_0x{op:02X}", ""))
        offset = pc
        pc += 1
        operands = []
        for ch in fmt:
            if ch == "B" and pc < n:
                operands.append(code[pc])
                pc += 1
            elif ch == "b" and pc < n:
                operands.append(struct.unpack("b", code[pc : pc + 1])[0])
                pc += 1
            elif ch == "I" and pc + 4 <= n:
                operands.append(struct.unpack("<I", code[pc : pc + 4])[0])
                pc += 4
            elif ch == "i" and pc + 4 <= n:
                operands.append(struct.unpack("<i", code[pc : pc + 4])[0])
                pc += 4

        note = ""
        if name in ("PUSH1", "PUSH4") and operands:
            idx = operands[0]
            if 0 <= idx < len(lit_vals):
                preview = lit_vals[idx].replace("\n", "\\n")
                if len(preview) > 60:
                    preview = preview[:57] + "..."
                note = f'lit[{idx}] = "{preview}"'
        elif "JUMP" in name and operands:
            note = f"target -> {offset + operands[0]}"

        insns.append(
            {
                "PC": offset,
                "Opcode": name,
                "Operands": ", ".join(str(x) for x in operands) if operands else "-",
                "Referensi": note or "-",
            }
        )
        if name == "DONE":
            break

    return insns


def decompile_tcl83(code: bytes, literals: list) -> tuple:
    """Reconstruct runnable Tcl source statements from Tcl 8.3 bytecode."""
    insns = disassemble_bytecode(code, literals)
    lit_vals = [x["value"] for x in literals]
    stack = []
    statements = []
    has_complex_branch = any(
        ins["Opcode"] in ("JUMP_TRUE1", "JUMP_TRUE4", "JUMP_FALSE1", "JUMP_FALSE4", "FOREACH_START4")
        for ins in insns
    )

    def get_lit(idx: int) -> str:
        return lit_vals[idx] if 0 <= idx < len(lit_vals) else f"LIT_{idx}"

    def pop_n(count: int) -> list:
        if count <= 0:
            return []
        if len(stack) >= count:
            items = stack[-count:]
            del stack[-count:]
            return items
        res = list(stack)
        stack.clear()
        return [TclExpr("lit", "?")] * (count - len(res)) + res

    bin_ops = {
        "EQ": "==",
        "NEQ": "!=",
        "LT": "<",
        "GT": ">",
        "LE": "<=",
        "GE": ">=",
        "ADD": "+",
        "SUB": "-",
        "MULT": "*",
        "DIV": "/",
        "MOD": "%",
        "LOR": "||",
        "LAND": "&&",
    }

    for i, ins in enumerate(insns):
        op = ins["Opcode"]
        raw_args = ins["Operands"]
        args = [int(x) for x in raw_args.split(", ")] if raw_args != "-" else []
        next_op = insns[i + 1]["Opcode"] if i + 1 < len(insns) else "DONE"

        if op in ("PUSH1", "PUSH4"):
            stack.append(TclExpr("lit", get_lit(args[0])))

        elif op == "DUP":
            if stack:
                stack.append(stack[-1])

        elif op == "POP":
            if stack:
                top = stack.pop()
                if top.kind == "cmd" and not getattr(top, "already_emitted", False):
                    statements.append(top.value)

        elif op == "CONCAT1":
            items = pop_n(args[0])
            flat = []
            for it in items:
                if it.kind == "concat":
                    flat.extend(it.parts)
                else:
                    flat.append(it)
            stack.append(TclExpr("concat", "", parts=flat))

        elif op in ("INVOKE_STK1", "INVOKE_STK4"):
            items = pop_n(args[0])
            cmd_str = " ".join(it.as_word() for it in items)
            expr = TclExpr("cmd", cmd_str)
            if next_op == "POP":
                expr.already_emitted = True
                statements.append(cmd_str)
            stack.append(expr)

        elif op in ("LOAD_SCALAR1", "LOAD_SCALAR4"):
            stack.append(TclExpr("var", f"local_{args[0]}"))

        elif op == "LOAD_SCALAR_STK":
            name_expr = pop_n(1)[0]
            stack.append(TclExpr("var", name_expr.value))

        elif op in ("STORE_SCALAR1", "STORE_SCALAR4"):
            val_expr = pop_n(1)[0]
            stmt = f"set local_{args[0]} {val_expr.as_word()}"
            if next_op == "POP":
                statements.append(stmt)
                expr = TclExpr("cmd", stmt)
                expr.already_emitted = True
                stack.append(expr)
            else:
                stack.append(TclExpr("cmd", stmt))

        elif op == "STORE_SCALAR_STK":
            name_expr, val_expr = pop_n(2)
            stmt = f"set {name_expr.value} {val_expr.as_word()}"
            if next_op == "POP":
                statements.append(stmt)
                expr = TclExpr("cmd", stmt)
                expr.already_emitted = True
                stack.append(expr)
            else:
                stack.append(TclExpr("cmd", stmt))

        elif op in ("STORE_ARRAY1", "STORE_ARRAY4"):
            idx_expr, val_expr = pop_n(2)
            stmt = f"set local_{args[0]}({idx_expr.value}) {val_expr.as_word()}"
            statements.append(stmt)
            expr = TclExpr("cmd", stmt)
            expr.already_emitted = True
            stack.append(expr)

        elif op == "STORE_ARRAY_STK":
            name_expr, idx_expr, val_expr = pop_n(3)
            stmt = f"set {name_expr.value}({idx_expr.value}) {val_expr.as_word()}"
            statements.append(stmt)
            expr = TclExpr("cmd", stmt)
            expr.already_emitted = True
            stack.append(expr)

        elif op in ("LOAD_ARRAY1", "LOAD_ARRAY4"):
            idx_expr = pop_n(1)[0]
            stack.append(TclExpr("var", f"local_{args[0]}({idx_expr.value})"))

        elif op == "LOAD_ARRAY_STK":
            name_expr, idx_expr = pop_n(2)
            stack.append(TclExpr("var", f"{name_expr.value}({idx_expr.value})"))

        elif op in ("INCR_SCALAR1_IMM", "INCR_SCALAR1"):
            delta = args[1] if len(args) > 1 else 1
            stmt = f"incr local_{args[0]} {delta}"
            statements.append(stmt)
            stack.append(TclExpr("cmd", stmt))

        elif op in ("INCR_SCALAR_STK_IMM", "INCR_SCALAR_STK"):
            name_expr = pop_n(1)[0]
            delta = args[0] if args else 1
            stmt = f"incr {name_expr.value} {delta}"
            statements.append(stmt)
            stack.append(TclExpr("cmd", stmt))

        elif op == "EVAL_STK":
            body_expr = pop_n(1)[0]
            stmt = f"eval {body_expr.as_word()}"
            if next_op == "POP":
                statements.append(stmt)
            stack.append(TclExpr("cmd", stmt))

        elif op == "EXPR_STK":
            e = pop_n(1)[0]
            stack.append(TclExpr("cmd", f"expr {e.as_word()}"))

        elif op in bin_ops:
            a, b = pop_n(2)
            stack.append(TclExpr("cmd", f"expr {{{a.as_word()} {bin_ops[op]} {b.as_word()}}}"))

        elif op == "LNOT":
            a = pop_n(1)[0]
            stack.append(TclExpr("cmd", f"expr {{!{a.as_word()}}}"))

        elif op == "DONE":
            break

    return statements, (not has_complex_branch)


def convert_tbc_to_tcl(raw_text: str, source_filename: str = "macro.tbc") -> dict:
    """Parse TclPro ByteCode (.tbc) and convert it into a clean .tcl script."""
    match = re.search(r"tbcload::bceval\s*\{(.*)\}", raw_text, re.DOTALL)
    if not match:
        return {
            "ok": False,
            "error": "Blok 'tbcload::bceval { ... }' tidak ditemukan. Pastikan file adalah TclPro ByteCode (.tbc).",
        }

    body = match.group(1).strip()
    lines = [line.rstrip("\r") for line in body.splitlines()]

    if not lines or not lines[0].startswith("TclPro ByteCode"):
        return {
            "ok": False,
            "error": "Header 'TclPro ByteCode' tidak valid atau korup.",
        }

    header = lines[0]
    counts = lines[1].split() if len(lines) > 1 else []
    try:
        num_commands = int(counts[0])
        num_code_bytes = int(counts[2])
        num_literals = int(counts[3])
    except (IndexError, ValueError):
        return {
            "ok": False,
            "error": "Metadata ukuran bytecode pada baris ke-2 tidak terbaca.",
        }

    meta = {
        "header": header,
        "num_commands": num_commands,
        "num_bytecode_bytes": num_code_bytes,
        "num_literals": num_literals,
    }

    idx = 2
    code_bytes = b""
    if idx < len(lines) and lines[idx].strip().isdigit():
        c_len = int(lines[idx].strip())
        code_bytes, idx = read_a85_block(lines, idx + 1, c_len)

    if idx < len(lines) and lines[idx].strip().isdigit():
        d_len = int(lines[idx].strip())
        _, idx = read_a85_block(lines, idx + 1, d_len)

    if idx < len(lines) and lines[idx].strip().isdigit():
        l_len = int(lines[idx].strip())
        _, idx = read_a85_block(lines, idx + 1, l_len)

    if idx < len(lines) and lines[idx].strip().isdigit():
        idx += 1

    literals = []
    while idx < len(lines) and len(literals) < num_literals:
        tag = lines[idx].strip()
        if tag in ("x", "s"):
            idx += 1
            if idx >= len(lines):
                break
            byte_len = int(lines[idx].strip())
            decoded, idx = read_a85_block(lines, idx + 1, byte_len)
            text_val = decoded.decode("utf-8", errors="replace")
            literals.append(
                {
                    "Index": len(literals),
                    "Tipe": "string",
                    "Byte": byte_len,
                    "Isi Terdekode": text_val,
                    "value": text_val,
                }
            )
        elif tag in ("i", "d"):
            idx += 1
            val = lines[idx].strip() if idx < len(lines) else ""
            idx += 1
            literals.append(
                {
                    "Index": len(literals),
                    "Tipe": "number",
                    "Byte": len(val),
                    "Isi Terdekode": val,
                    "value": val,
                }
            )
        else:
            idx += 1

    disasm = disassemble_bytecode(code_bytes, literals) if code_bytes else []
    statements, is_complete = decompile_tcl83(code_bytes, literals) if code_bytes else ([], False)

    banner_comments = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") and "TclPro::Compiler" not in stripped:
            banner_comments.append(line.rstrip())
        elif "tbcload" in stripped or stripped.startswith("if {"):
            break

    out_lines = []
    if banner_comments:
        out_lines.extend(banner_comments)
        out_lines.append("")

    if not is_complete:
        out_lines.append("# PERINGATAN: File ini memiliki percabangan (if/loop) dalam bytecode.")
        out_lines.append("# Periksa kembali alur logika di bawah sebelum menjalankan di Surpac.")
        out_lines.append("")

    if statements:
        for stmt in statements:
            out_lines.append(stmt)
            if "SclFunction" in stmt:
                out_lines.append("")
    else:
        out_lines.append("# Fallback rekonstruksi dari tabel literal:")
        values = [item["value"] for item in literals]
        k = 0
        while k < len(values):
            if k + 1 < len(values) and re.search(r"frm\d{5}\s*=", values[k + 1]):
                out_lines.append(f'set status [ SclFunction "{values[k]}" {{{values[k + 1]}}}]')
                out_lines.append("")
                k += 2
            else:
                out_lines.append(f"# [{k}] {values[k]}")
                k += 1

    tcl_output = "\n".join(out_lines).rstrip() + "\n"

    p = Path(source_filename or "macro.tbc")
    if p.suffix.lower() == ".tbc":
        out_name = p.with_suffix(".tcl").name
    else:
        out_name = f"{p.stem}_decompiled.tcl"

    scl_calls = re.findall(r'SclFunction\s+"([^"]+)"', tcl_output)

    return {
        "ok": True,
        "output_filename": out_name,
        "tcl_code": tcl_output,
        "meta": meta,
        "scl_functions": scl_calls,
        "literals": literals,
        "disassembly": disasm,
        "is_complete": is_complete,
    }


# ==============================================================================
# 3. STREAMLIT UI
# ==============================================================================
st.set_page_config(
    page_title="TBC → TCL Converter",
    page_icon="🔄",
    layout="wide",
)

st.title("Macro Converter: `.TBC` → `.TCL`")
st.caption(
    "Decompiler ByteCode TclPro 1.3 (Tcl 8.3) untuk Makro GEOVIA Surpac · "
    "Created by: **Michael Aragorn Purba**"
)

if "last_result" not in st.session_state:
    st.session_state["last_result"] = None

tab_single, tab_batch, tab_inspector = st.tabs(
    [
        "1. Convert Single File (.tbc → .tcl)",
        "2. Batch Convert (Multi-File + ZIP)",
        "3. ByteCode & Literal Inspector",
    ]
)

# ------------------------------------------------------------------------------
# TAB 1: SINGLE FILE
# ------------------------------------------------------------------------------
with tab_single:
    col_in, col_out = st.columns(2, gap="large")

    with col_in:
        st.subheader("Input File `.TBC`")
        uploaded_file = st.file_uploader(
            "Pilih file .tbc (atau file .tcl yang berisi tbcload)",
            type=["tbc", "tcl", "txt"],
            key="single_uploader",
        )

        default_text = ""
        source_name = "macro.tbc"
        if uploaded_file is not None:
            source_name = uploaded_file.name
            default_text = uploaded_file.getvalue().decode("utf-8", errors="replace")

        raw_input = st.text_area(
            "Atau tempel (paste) isi file `tbcload::bceval` di bawah ini:",
            value=default_text,
            height=360,
            placeholder="tbcload::bceval {\nTclPro ByteCode 1 0 1.3 8.3\n...",
        )

        convert_clicked = st.button("Convert ke .TCL", type="primary", use_container_width=True)

    with col_out:
        st.subheader("Output Skrip `.TCL`")

        if (uploaded_file is not None or convert_clicked) and raw_input.strip():
            result = convert_tbc_to_tcl(raw_input, source_name)
            st.session_state["last_result"] = result
        elif convert_clicked and not raw_input.strip():
            st.warning("Masukkan atau unggah file `.tbc` terlebih dahulu.")

        res = st.session_state["last_result"]
        if res is None:
            st.info("Unggah file `.tbc` di panel kiri untuk melihat hasil konversi `.tcl`.")
        elif not res["ok"]:
            st.error(res["error"])
        else:
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("File Output", res["output_filename"])
            m2.metric("SclFunction", f"{len(res['scl_functions'])} fungsi")
            m3.metric("Literal", f"{len(res['literals'])}/{res['meta']['num_literals']}")
            m4.metric("Instruksi VM", f"{len(res['disassembly'])}")

            st.download_button(
                label=f"⬇️ Unduh {res['output_filename']}",
                data=res["tcl_code"].encode("utf-8"),
                file_name=res["output_filename"],
                mime="text/plain",
                use_container_width=True,
            )

            st.code(res["tcl_code"], language="tcl", line_numbers=True)

# ------------------------------------------------------------------------------
# TAB 2: BATCH CONVERT
# ------------------------------------------------------------------------------
with tab_batch:
    st.subheader("Konversi Banyak File Sekaligus (`.TBC` → `.TCL`)")
    batch_files = st.file_uploader(
        "Pilih beberapa file .tbc sekaligus",
        type=["tbc", "tcl", "txt"],
        accept_multiple_files=True,
        key="batch_uploader",
    )

    if batch_files:
        summary_rows = []
        valid_outputs = []

        for f in batch_files:
            content = f.getvalue().decode("utf-8", errors="replace")
            conv = convert_tbc_to_tcl(content, f.name)
            if conv["ok"]:
                summary_rows.append(
                    {
                        "File Asal": f.name,
                        "File Output": conv["output_filename"],
                        "SclFunction": len(conv["scl_functions"]),
                        "Literal": len(conv["literals"]),
                        "Status": "✅ Sukses",
                    }
                )
                valid_outputs.append((conv["output_filename"], conv["tcl_code"]))
            else:
                summary_rows.append(
                    {
                        "File Asal": f.name,
                        "File Output": "-",
                        "SclFunction": 0,
                        "Literal": 0,
                        "Status": f"❌ {conv['error']}",
                    }
                )

        st.dataframe(summary_rows, use_container_width=True, hide_index=True)

        if valid_outputs:
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                for out_fname, code_str in valid_outputs:
                    zf.writestr(out_fname, code_str)

            st.download_button(
                label=f"📦 Unduh Semua ({len(valid_outputs)} File .TCL dalam .ZIP)",
                data=zip_buffer.getvalue(),
                file_name="converted_surpac_macros.zip",
                mime="application/zip",
            )
    else:
        st.info("Pilih beberapa file `.tbc` di atas untuk melakukan konversi massal.")

# ------------------------------------------------------------------------------
# TAB 3: INSPECTOR
# ------------------------------------------------------------------------------
with tab_inspector:
    res = st.session_state["last_result"]
    if not res or not res.get("ok"):
        st.info("Jalankan konversi pada **Tab 1** terlebih dahulu untuk melihat tabel literal dan disassembly bytecode.")
    else:
        c_lit, c_vm = st.columns(2, gap="large")
        with c_lit:
            st.subheader(f"Tabel Literal ({len(res['literals'])} item)")
            clean_lits = [
                {
                    "Index": item["Index"],
                    "Tipe": item["Tipe"],
                    "Byte": item["Byte"],
                    "Isi Terdekode": item["Isi Terdekode"],
                }
                for item in res["literals"]
            ]
            st.dataframe(clean_lits, use_container_width=True, hide_index=True, height=500)

        with c_vm:
            st.subheader(f"Disassembly ByteCode VM ({len(res['disassembly'])} instruksi)")
            st.dataframe(res["disassembly"], use_container_width=True, hide_index=True, height=500)

# ------------------------------------------------------------------------------
# FOOTER CREDIT
# ------------------------------------------------------------------------------
st.divider()
st.markdown(
    "<div style='text-align: center; color: #888; font-size: 0.85rem;'>"
    "Created by: <strong>Michael Aragorn Purba</strong>"
    "</div>",
    unsafe_allow_html=True,
)

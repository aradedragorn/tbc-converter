# Surpac Macro Converter (`.TBC` → `.TCL`)

Web dashboard berbasis Streamlit untuk mendekode dan mendekompilasi file makro terkompilasi TclPro ByteCode (`.tbc` / `tbcload 1.3`) menjadi skrip sumber `.tcl` yang kompatibel dengan GEOVIA Surpac.

**Created by: Michael Aragorn Purba**

## Fitur Utama
- **Single File Converter:** Unggah atau *paste* isi file `.tbc` untuk langsung menghasilkan skrip `.tcl` lengkap beserta pratinjau sintaks.
- **Batch Converter:** Konversi banyak file `.tbc` sekaligus dan unduh seluruh hasilnya dalam satu arsip `.zip`.
- **ByteCode & Literal Inspector:** Inspeksi tabel literal string dan urutan *opcode* mesin virtual Tcl 8.3.

## Menjalankan Secara Lokal
```bash
pip install -r requirements.txt
streamlit run app_tbc_to_tcl.py

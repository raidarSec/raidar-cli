import argparse
import pickletools
import os
import nbformat

# --- Risky patterns to flag ---
RISKY_OPCODES = ['GLOBAL', 'EXEC', 'EVAL']
RISKY_CODE_PATTERNS = ['os.system', 'subprocess', 'eval', 'exec']

def scan_pickle(path):
    print(f"\n🔍 Scanning Pickle file: {path}")
    risky_found = False
    try:
        with open(path, 'rb') as f:
            for opcode, arg, pos in pickletools.genops(f):
                if opcode.name in RISKY_OPCODES:
                    print(f"⚠️ Risky opcode found: {opcode.name} at byte {pos}")
                    risky_found = True
        if not risky_found:
            print("✅ No risky opcodes found. Pickle appears safe for deserialization.")
    except Exception as e:
        print(f"❌ Error scanning pickle file: {e}")

def scan_notebook(path):
    print(f"\n📓 Scanning Notebook: {path}")
    risky_cells = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            nb = nbformat.read(f, as_version=4)
        for i, cell in enumerate(nb.cells):
            if cell.cell_type == 'code':
                code = cell.source
                for pattern in RISKY_CODE_PATTERNS:
                    if pattern in code:
                        risky_cells.append((i + 1, pattern, code.strip()))
        if risky_cells:
            print("⚠️ Risky code patterns found:")
            for cell_num, pattern, snippet in risky_cells:
                print(f"  - Cell {cell_num}: contains '{pattern}'\n    → {snippet[:100]}...")
        else:
            print("✅ No risky code patterns found in notebook.")
    except Exception as e:
        print(f"❌ Error scanning notebook: {e}")

def main():
    parser = argparse.ArgumentParser(description="MLSecOps Artifact Scanner")
    parser.add_argument("path", help="Path to file (.pkl or .ipynb)")
    args = parser.parse_args()

    if os.path.isfile(args.path):
        if args.path.endswith('.pkl'):
            scan_pickle(args.path)
        elif args.path.endswith('.ipynb'):
            scan_notebook(args.path)
        else:
            print("⚠️ Unsupported file type. Use .pkl or .ipynb")
    else:
        print("📁 Directory scanning not yet supported.")

if __name__ == "__main__":
    main()
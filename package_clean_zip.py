"""
ARENA X 2026 // Clean Distribution Packager
Generates a sanitized production archive excluding all sensitive runtime files,
such as .env, .venv, .vscode, data/, uploads/, SQLite databases, and caches.
"""

import os
import zipfile
import sys

EXCLUDE_DIRS = {
    '.venv', 'venv', 'ENV', 'env',
    '.vscode', '.idea',
    'data', 'uploads',
    '__pycache__', '.pytest_cache',
    '.git'
}

EXCLUDE_EXTENSIONS = {
    '.db', '.sqlite', '.sqlite3', '.db-journal', '.db-wal', '.db-shm',
    '.pyc', '.pyo', '.pyd', '.backup', '.bak', '.pem', '.key', '.cert'
}

EXCLUDE_EXACT_FILES = {
    '.env', '.env.production', '.env.local', '.env.production.sample', 'debug_js.txt', 'scratch_script_0.js'
}

def create_clean_zip(output_zip_name="arena_x_2026_clean_portal.zip"):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(base_dir, output_zip_name)

    print(f"[*] Packaging clean release to: {output_path}")
    count = 0

    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(base_dir):
            # Prune excluded directories in-place
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith('.')]

            for file in files:
                rel_path = os.path.relpath(os.path.join(root, file), base_dir)
                ext = os.path.splitext(file)[1].lower()

                # Filter out excluded items
                if file in EXCLUDE_EXACT_FILES or ext in EXCLUDE_EXTENSIONS or file.endswith('.zip'):
                    continue

                full_path = os.path.join(root, file)
                zf.write(full_path, rel_path)
                count += 1

        # Include empty data/ and uploads/ placeholders
        zf.writestr('data/.gitkeep', '')
        zf.writestr('uploads/.gitkeep', '')

    print(f"[SUCCESS] Clean ZIP created successfully with {count} files.")
    print(f"[NOTICE] Verified that .env, .venv, .vscode, data/ databases, uploads/ files are EXCLUDED.")

if __name__ == '__main__':
    zip_name = sys.argv[1] if len(sys.argv) > 1 else "arena_x_2026_clean_portal.zip"
    create_clean_zip(zip_name)

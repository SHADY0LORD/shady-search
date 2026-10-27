#!/usr/bin/env python3
"""Read-only inventory of a SQLite source DB. Prints schema/count metadata only, not customer rows."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        print("Usage: python backend/inspect_source_db.py path/to/customers.db", file=sys.stderr)
        raise SystemExit(2)
    path = Path(sys.argv[1]).expanduser().resolve()
    if not path.is_file():
        print("ERROR: database file not found", file=sys.stderr)
        raise SystemExit(2)

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    # mode=ro prevents accidental writes to the source database.
    uri = path.as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        tables = []
        for row in conn.execute(
            "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ):
            item = {"name": row["name"], "type": row["type"]}
            if row["type"] == "table":
                cols = list(conn.execute(f'PRAGMA table_info("{row["name"].replace(chr(34), chr(34)*2)}")'))
                item["columns"] = [
                    {"name": c["name"], "type": c["type"], "notnull": bool(c["notnull"]), "pk": c["pk"]}
                    for c in cols
                ]
                indexes = list(conn.execute(f'PRAGMA index_list("{row["name"].replace(chr(34), chr(34)*2)}")'))
                item["indexes"] = [{"name": ix["name"], "unique": bool(ix["unique"])} for ix in indexes]
                try:
                    item["row_count"] = conn.execute(
                        f'SELECT COUNT(*) FROM "{row["name"].replace(chr(34), chr(34)*2)}"'
                    ).fetchone()[0]
                except sqlite3.DatabaseError as exc:
                    item["row_count_error"] = type(exc).__name__
            tables.append(item)

        result = {
            "file_name": path.name,
            "file_size_bytes": path.stat().st_size,
            "sha256": digest.hexdigest(),
            "sqlite_version": sqlite3.sqlite_version,
            "tables": tables,
        }
        # A summary of area cardinality is useful but does not reveal area values.
        for table in tables:
            if table.get("name") == "customers" and any(c["name"] == "area" for c in table.get("columns", [])):
                try:
                    table["distinct_nonempty_area_count"] = conn.execute(
                        "SELECT COUNT(DISTINCT area) FROM customers WHERE area IS NOT NULL AND area != ''"
                    ).fetchone()[0]
                except sqlite3.DatabaseError:
                    pass
        print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        conn.close()


if __name__ == "__main__":
    main()

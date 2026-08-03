from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import uvicorn

from archon.importer import apply_import, parse_guard_config
from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.repo import ServerRepo


def _run_server() -> None:
    settings = Settings()
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True)

    async def _make_app():
        db = Database(Path(settings.data_dir))
        await db.connect()
        return create_app(settings, db)

    app = asyncio.run(_make_app())
    uvicorn.run(app, host=settings.host, port=settings.port)


async def _run_import(path: str, dry_run: bool) -> None:
    settings = Settings()
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True)

    yaml_text = Path(path).read_text()
    result = parse_guard_config(yaml_text)

    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)

    db = Database(Path(settings.data_dir))
    await db.connect()
    try:
        repo = ServerRepo(db)
        actions = await apply_import(repo, result, dry_run=dry_run)
        for action in actions:
            print(action)
        if dry_run:
            print(f"\n(dry run — {len(result.servers)} server(s) would be imported, nothing written)")
        else:
            print(f"\nimported {len(result.servers)} server(s)")
    finally:
        await db.close()


def cli() -> None:
    parser = argparse.ArgumentParser(prog="argus")
    subparsers = parser.add_subparsers(dest="command")

    import_parser = subparsers.add_parser("import", help="Import a mcp-guard guard-config.yml")
    import_parser.add_argument("path", help="Path to guard-config.yml")
    import_parser.add_argument("--dry-run", action="store_true", help="Parse and print without writing")

    args = parser.parse_args()

    if args.command == "import":
        asyncio.run(_run_import(args.path, args.dry_run))
    else:
        _run_server()


if __name__ == "__main__":
    cli()

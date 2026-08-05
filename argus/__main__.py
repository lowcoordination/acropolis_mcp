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

    # §26 (review 2026-08-04): this builds the app (including db.connect(), which constructs
    # asyncio.Lock/Queue instances) inside a THROWAWAY asyncio.run() loop, then hands the
    # resulting app to uvicorn.run(), which creates a SEPARATE, second event loop to actually
    # serve requests — a real cross-loop hazard in principle. Considered fixing via uvicorn's
    # `factory=True`, but confirmed by reading uvicorn's Config.load() (self.loaded_app =
    # self.loaded_app(), a plain synchronous call) that it does NOT support an async factory —
    # it would call this and get back an unawaited coroutine object instead of an app, a worse
    # bug than the one being fixed. Left as-is: Python 3.10+'s asyncio.Lock/Queue defer loop
    # binding to first real use rather than construction, and nothing in the first loop here
    # ever uses one of these primitives, so the cross-loop construction is currently safe in
    # practice, just not guaranteed by the primitives' public contract. A real fix needs
    # uvicorn's `Server` class driven directly inside one loop rather than `uvicorn.run()`,
    # which is a bigger change than this cleanup pass warrants.
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

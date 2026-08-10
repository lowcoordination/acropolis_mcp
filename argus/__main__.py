from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import uvicorn

from archon.config_io import export_config, plan_import
from archon.importer import apply_import, parse_guard_config
from archon.settings import Settings
from argus.app import create_app
from db.database import Database
from db.repo import ServerRepo, SettingsRepo


def _make_db(settings: Settings) -> Database:
    """Build the Database from settings.

    Enterprise #7: this used to be `Database(Path(settings.data_dir))` at five call sites. It is
    now one helper because the construction takes three settings rather than one, and because
    every entry point (server, import, export, import-config, check) must fail the same way with
    the same message when ACROPOLIS_DATABASE_URL is unset — Database.__init__ raises
    DatabaseNotConfiguredError, which names the variable and points at docs/postgres.md.
    """
    return Database(
        settings.database_url,
        writer_pool_max=settings.db_writer_pool_max,
        reader_pool_max=settings.db_reader_pool_max,
    )


def _run_server() -> None:
    settings = Settings()
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True)

    # §26 (review 2026-08-04) + 2026-08-10 follow-up: the original implementation built the app
    # (including db.connect(), which constructs asyncio.Lock/Queue and — post-cutover, the
    # asyncpg pools) inside a THROWAWAY asyncio.run() loop, then handed the app to
    # uvicorn.run(), which creates a SEPARATE, second event loop to actually serve requests. The
    # 2026-08-04 review accepted this as "safe in practice, not guaranteed by the primitives'
    # public contract" — Python 3.12's asyncio deferred loop binding enough that the pools never
    # noticed. Python 3.14's stricter asyncio makes it a hard failure: the pools' first
    # connection attempt on uvicorn's loop raises RuntimeError('Event loop is closed') and the
    # gateway never comes up. The review's own prescription for the real fix is used here:
    # drive uvicorn's `Server` class directly inside ONE loop that also owns the db + app, so
    # the pools' loop is the serving loop by construction. Server.serve() runs the lifespan
    # (start/stop of the background jobs) and blocks until shutdown; db.close() then runs on
    # the same loop that owns its pools.
    async def _run() -> None:
        db = _make_db(settings)
        await db.connect()
        try:
            app = create_app(settings, db)
            config = uvicorn.Config(app, host=settings.host, port=settings.port)
            server = uvicorn.Server(config)
            await server.serve()
        finally:
            await db.close()

    asyncio.run(_run())


async def _run_import(path: str, dry_run: bool) -> None:
    settings = Settings()
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True)

    yaml_text = Path(path).read_text()
    result = parse_guard_config(yaml_text)

    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)

    db = _make_db(settings)
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


async def _run_export(path: str | None, include_credentials: bool, stable: bool = False) -> None:
    settings = Settings()
    db = _make_db(settings)
    await db.connect()
    try:
        result = await export_config(
            ServerRepo(db), SettingsRepo(db), include_credentials=include_credentials
        )
        # Warnings go to stderr so `argus export > config.yaml` still produces a clean file
        # while the operator sees that credentials were withheld.
        for warning in result.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        text = result.to_stable_yaml() if stable else result.to_yaml()
        if path:
            Path(path).write_text(text)
            print(f"wrote {path}", file=sys.stderr)
        else:
            print(text, end="")
    finally:
        await db.close()


async def _run_import_config(path: str, apply: bool) -> None:
    settings = Settings()
    db = _make_db(settings)
    await db.connect()
    try:
        plan = await plan_import(
            ServerRepo(db), SettingsRepo(db), Path(path).read_text(), apply=apply
        )
        for error in plan.errors:
            print(f"error: {error}", file=sys.stderr)
        for warning in plan.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        for action in plan.actions:
            print(action.describe(applied=apply))

        if not plan.ok:
            print("\nnothing was written (file rejected)", file=sys.stderr)
            raise SystemExit(1)
        if apply:
            print(f"\napplied {len(plan.actions)} action(s)")
        else:
            print("\n(dry run — nothing written; re-run with --apply)")
    finally:
        await db.close()


async def _run_check(path: str) -> int:
    """Check whether live config matches the file. Returns exit code: 0=in sync, 1=drift, 2=invalid.

    This is the CI primitive for GitOps: run in a pipeline to detect drift between the
    committed config file and the live gateway state. Three distinct exit codes because CI
    needs to distinguish "config drifted" (actionable) from "file is malformed" (fix the file).
    """
    settings = Settings()
    db = _make_db(settings)
    await db.connect()
    try:
        plan = await plan_import(
            ServerRepo(db), SettingsRepo(db), Path(path).read_text(), apply=False
        )

        if not plan.ok:
            # Invalid file — parse errors, validation failures, etc.
            for error in plan.errors:
                print(f"error: {error}", file=sys.stderr)
            return 2

        # Check for drift: any action that isn't "unchanged" means live state differs from file
        drift_actions = [a for a in plan.actions if a.kind != "unchanged"]
        if drift_actions:
            print("config drift detected:", file=sys.stderr)
            for action in drift_actions:
                print(f"  {action.describe(applied=False)}", file=sys.stderr)
            return 1

        # In sync
        return 0
    finally:
        await db.close()


def cli() -> None:
    parser = argparse.ArgumentParser(prog="argus")
    subparsers = parser.add_subparsers(dest="command")

    import_parser = subparsers.add_parser("import", help="Import a mcp-guard guard-config.yml")
    import_parser.add_argument("path", help="Path to guard-config.yml")
    import_parser.add_argument("--dry-run", action="store_true", help="Parse and print without writing")

    export_parser = subparsers.add_parser("export", help="Export this gateway's config as YAML")
    export_parser.add_argument("-o", "--output", help="Write to a file instead of stdout")
    export_parser.add_argument(
        "--include-credentials", action="store_true",
        help="Include plaintext upstream credentials (the file becomes a secret)",
    )
    export_parser.add_argument(
        "--stable", action="store_true",
        help="Omit the exported_at timestamp — for committed exports that should be byte-identical",
    )

    import_config_parser = subparsers.add_parser(
        "import-config", help="Import an Acropolis config export (dry run unless --apply)"
    )
    import_config_parser.add_argument("path", help="Path to an exported YAML file")
    # Mirrors the HTTP API: preview is the default, writing is the explicit opt-in.
    import_config_parser.add_argument(
        "--apply", action="store_true", help="Actually write the changes (default: dry run)"
    )

    check_parser = subparsers.add_parser(
        "check", help="Check whether live config matches a file (exit 0=in sync, 1=drift, 2=invalid)"
    )
    check_parser.add_argument("path", help="Path to an exported YAML file")

    args = parser.parse_args()

    if args.command == "import":
        asyncio.run(_run_import(args.path, args.dry_run))
    elif args.command == "export":
        asyncio.run(_run_export(args.output, args.include_credentials, args.stable))
    elif args.command == "import-config":
        asyncio.run(_run_import_config(args.path, args.apply))
    elif args.command == "check":
        exit_code = asyncio.run(_run_check(args.path))
        raise SystemExit(exit_code)
    else:
        _run_server()


if __name__ == "__main__":
    cli()

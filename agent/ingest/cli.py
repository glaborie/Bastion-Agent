"""``python -m agent.ingest.cli``: redact a PDF, or restore an artifact.

    python -m agent.ingest.cli convert dossier.pdf \\
        --tenant acme --actor alice --output dossier.redacted.md

    python -m agent.ingest.cli restore dossier.redacted.md \\
        --tenant acme --actor alice --source dossier.pdf --output dossier.md

``convert`` writes the artifact only after the whole file has been parsed and
redacted, so a failure leaves an existing path untouched. ``restore`` derives the
vault session from the original PDF and reports markers whose 30-minute entries
have expired instead of pretending they were restored (ADR-023).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from anyio import to_thread

from agent.dlp.presidio import PresidioDLP, get_dlp
from agent.ingest.document import IngestError, ingest, restore, session_for


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agent.ingest.cli",
        description="Convert a PDF to DLP-redacted Markdown, or restore the markers.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    convert = commands.add_parser("convert", help="PDF -> Markdown with vault markers")
    convert.add_argument("source", type=Path)
    convert.add_argument("--tenant", required=True)
    convert.add_argument(
        "--actor", required=True, help="the immutable subject the session is scoped to"
    )
    convert.add_argument("--output", type=Path, required=True)

    restore_cmd = commands.add_parser(
        "restore", help="restore markers for the same tenant and session"
    )
    restore_cmd.add_argument("artifact", type=Path)
    restore_cmd.add_argument("--tenant", required=True)
    restore_cmd.add_argument("--actor", required=True)
    restore_cmd.add_argument(
        "--source", type=Path, required=True, help="the PDF the artifact was produced from"
    )
    restore_cmd.add_argument("--output", type=Path, default=None, help="default: stdout")
    return parser


async def _convert(args: argparse.Namespace, dlp: PresidioDLP) -> int:
    markdown, report = await ingest(
        args.source, tenant_id=args.tenant, actor_id=args.actor, dlp=dlp
    )
    args.output.write_text(markdown, encoding="utf-8")
    print(
        f"ingested {args.source.name}: {report.pages} page(s), "
        f"{report.entities} entity/entities ({', '.join(report.types) or 'none'}), "
        f"extractor {report.extractor}; artifact {args.output}",
        file=sys.stderr,
    )
    return 0


async def _restore(args: argparse.Namespace, dlp: PresidioDLP) -> int:
    source_bytes = await to_thread.run_sync(args.source.read_bytes)
    session_id = session_for(args.tenant, args.actor, source_bytes)
    text, expired = await restore(
        await to_thread.run_sync(_read_text, args.artifact),
        tenant_id=args.tenant,
        session_id=session_id,
        dlp=dlp,
    )
    if args.output is None:
        print(text)
    else:
        args.output.write_text(text, encoding="utf-8")
    if expired:
        print(
            f"restore: {expired} marker(s) expired (the vault entry outlived no session); "
            "left as markers",
            file=sys.stderr,
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    dlp = get_dlp()
    runner = _convert if args.command == "convert" else _restore
    try:
        return asyncio.run(runner(args, dlp))
    except IngestError as error:
        print(f"ingest: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

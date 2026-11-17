"""Local document ingestion: redaction before the text can reach a model.

The only binary input this control plane accepts is a PDF, and it is converted
with a pinned, plugin-free ``markitdown`` build inside the perimeter, then run
through the same ``PresidioDLP.redact`` the chat path uses. The artifact holds
vault markers scoped to ``ingest:<tenant, actor, input digest>``, so two files
cannot share markers, and nothing here calls OCR, Document Intelligence or a
model. See ADR-023 for the trust boundary and its limits.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from anyio import to_thread
from markitdown import MarkItDown

from agent.dlp.presidio import PresidioDLP
from settings import get_settings

logger = logging.getLogger(__name__)

#: The only accepted extension. The magic number is checked too: a renamed PNG
#: must fail rather than be handed to the parser.
PDF_SUFFIX = ".pdf"
PDF_MAGIC = b"%PDF-"
_PAGE = re.compile(rb"/Type\s*/Page(?![s])")
_MARKER = re.compile(r"\{\{ENTITY:[A-Z][A-Z0-9_]*_\d+\}\}")
SESSION_PREFIX = "ingest:"


class IngestError(RuntimeError):
    """The file is not an acceptable PDF, or it produced no text."""


class Extractor(Protocol):
    """Convert PDF bytes to Markdown. Injectable so tests need no parser."""

    name: str

    def convert(self, data: bytes) -> str: ...


class MarkItDownExtractor:
    """The one extractor this slice ships: no plugins, no network, no LLM.

    ``MarkItDown`` gains an ``llm_client`` and the ``docintel_*`` arguments only
    through its constructor, so constructing it with ``enable_plugins=False`` and
    nothing else is what keeps the conversion local (ADR-023 decision 3).
    """

    name = "markitdown"

    def __init__(self) -> None:
        self._converter = MarkItDown(enable_plugins=False)

    def convert(self, data: bytes) -> str:
        result = self._converter.convert_stream(io.BytesIO(data), file_extension=PDF_SUFFIX)
        return result.text_content


@dataclass(frozen=True, slots=True)
class IngestReport:
    """What the conversion did, never what the text said."""

    extractor: str
    pages: int
    characters: int
    entities: int
    types: tuple[str, ...]
    session_id: str


def session_for(tenant_id: str, actor_id: str, data: bytes) -> str:
    """Session id scoped to the tenant, actor and the exact input digest."""
    digest = hashlib.sha256(data).hexdigest()
    material = f"{tenant_id}\x00{actor_id}\x00{digest}".encode()
    return SESSION_PREFIX + hashlib.sha256(material).hexdigest()


def validate(data: bytes, path: Path, *, max_bytes: int) -> int:
    """Return the page count, or raise before any parser sees the file."""
    if path.suffix.lower() != PDF_SUFFIX:
        raise IngestError(f"only {PDF_SUFFIX} input is accepted, got {path.suffix or 'no suffix'}")
    if not data.startswith(PDF_MAGIC):
        raise IngestError(f"{path.name} is not a PDF (magic number)")
    if len(data) > max_bytes:
        raise IngestError(f"{path.name} is larger than the {max_bytes}-byte ceiling")
    if b"/Encrypt" in data:
        raise IngestError(f"{path.name} is encrypted")
    return len(_PAGE.findall(data))


def _extract(extractor: Extractor, data: bytes) -> str:
    return extractor.convert(data)


async def ingest(
    path: Path,
    *,
    tenant_id: str,
    actor_id: str,
    dlp: PresidioDLP,
    extractor: Extractor | None = None,
) -> tuple[str, IngestReport]:
    """Convert ``path`` to Markdown with every DLP entity already a marker."""
    settings = get_settings()
    data = await to_thread.run_sync(path.read_bytes)
    pages = validate(data, path, max_bytes=settings.document_max_bytes)
    if pages == 0:
        raise IngestError(f"{path.name} has no page")

    chosen = extractor or MarkItDownExtractor()
    try:
        markdown = await asyncio.wait_for(
            to_thread.run_sync(_extract, chosen, data),
            timeout=settings.document_parse_timeout_seconds,
        )
    except TimeoutError as exc:
        raise IngestError(
            f"{path.name} did not parse within {settings.document_parse_timeout_seconds}s"
        ) from exc
    except IngestError:
        raise
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # The parser sees untrusted bytes; any failure means "no artifact".
        raise IngestError(f"{path.name} could not be parsed: {type(exc).__name__}") from exc
    if not markdown.strip():
        raise IngestError(f"{path.name} yielded no text (scanned or empty PDF)")

    session_id = session_for(tenant_id, actor_id, data)
    redacted = await dlp.redact(markdown, session_id, tenant_id=tenant_id)
    types = tuple(sorted({entity.entity_type for entity in redacted.entities}))
    logger.info(
        "document ingested",
        extra={
            "extractor": chosen.name,
            "pages": pages,
            "characters": len(redacted.text),
            "entities": len(redacted.entities),
            "types": types,
        },
    )
    return redacted.text, IngestReport(
        extractor=chosen.name,
        pages=pages,
        characters=len(redacted.text),
        entities=len(redacted.entities),
        types=types,
        session_id=session_id,
    )


async def restore(
    text: str,
    *,
    tenant_id: str,
    session_id: str,
    dlp: PresidioDLP,
) -> tuple[str, int]:
    """Restore markers for this session and report how many had expired."""
    restored = await dlp.restore(text, session_id, tenant_id=tenant_id)
    # Whatever is still a marker was not in the vault any more: its entry expired.
    return restored, len(set(_MARKER.findall(restored)))

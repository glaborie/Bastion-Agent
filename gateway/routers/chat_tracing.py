"""GenAI span attributes for one chat turn (ADR-014 conventions, ADR-026 split).

Kept beside the router rather than inside it: ``chat.py`` is at pylint's module
limit and these helpers are the coherent, caller-free part to lift out. They
read nothing but the completion and the pinned model, so they carry no state.
"""

from __future__ import annotations

from opentelemetry.util.types import AttributeValue

from agent.routing.client import ChatCompletion
from telemetry import span_attributes as _attributes


def split_model(model: str) -> tuple[str, str]:
    """Split ``provider/model`` into its parts; a bare id is assumed local.

    OmniRoute answers ``openai/gpt-4o-mini`` and is configured with
    ``openrouter/openai/gpt-4o-mini``, so the pinned setting drops the router
    prefix and this split then yields the provider and the bare model id that
    backends key their price tables on.
    """
    provider, _, bare = model.partition("/")
    if not bare:
        return "local", provider
    return provider, bare


def completion_attributes(
    completion: ChatCompletion, *, requested: str
) -> dict[str, AttributeValue]:
    """GenAI semantic conventions OpenLit reads for model, tokens and cost.

    ``requested`` is the concrete model the alias is configured to use, not the
    alias itself: an alias is a routing label, and reporting it as a model makes
    every trace look like an unintended provider swap. When the router fails
    over to another model the mismatch is recorded as ``bastion.model.swapped``
    instead of being hidden.
    """
    provider, served = split_model(completion.model)
    _, pinned = split_model(requested)
    return _attributes(
        {
            "gen_ai.system": provider,
            "gen_ai.response.model": served,
            "bastion.model.swapped": served != pinned if pinned else None,
            "gen_ai.response.finish_reasons": (
                [completion.finish_reason] if completion.finish_reason else None
            ),
            "gen_ai.usage.input_tokens": completion.prompt_tokens,
            "gen_ai.usage.output_tokens": completion.completion_tokens,
            "gen_ai.usage.total_tokens": completion.total_tokens,
            "gen_ai.usage.cost": completion.cost_usd,
        }
    )

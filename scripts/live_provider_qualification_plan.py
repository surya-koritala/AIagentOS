#!/usr/bin/env python3
"""Build a bounded, fail-closed dispatch plan for live provider qualification."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys


SCHEMA_VERSION = 1
QUALIFICATION_CLASS = "live_provider_dispatch_plan"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PROVIDER_RE = re.compile(r"^[a-z][a-z0-9-]*$")
PROVIDER_CONFIGS = (
    {
        "provider": "openai",
        "model_variable": "OPENAI_QUALIFICATION_MODEL",
        "credential_secret": "OPENAI_API_KEY",
        "endpoint_secret": "UNUSED_PROVIDER_ENDPOINT",
    },
    {
        "provider": "anthropic",
        "model_variable": "ANTHROPIC_QUALIFICATION_MODEL",
        "credential_secret": "ANTHROPIC_API_KEY",
        "endpoint_secret": "UNUSED_PROVIDER_ENDPOINT",
    },
    {
        "provider": "azure-openai",
        "model_variable": "AZURE_OPENAI_QUALIFICATION_MODEL",
        "credential_secret": "AZURE_OPENAI_API_KEY",
        "endpoint_secret": "AZURE_OPENAI_ENDPOINT",
    },
    {
        "provider": "groq",
        "model_variable": "GROQ_QUALIFICATION_MODEL",
        "credential_secret": "GROQ_API_KEY",
        "endpoint_secret": "UNUSED_PROVIDER_ENDPOINT",
    },
    {
        "provider": "deepseek",
        "model_variable": "DEEPSEEK_QUALIFICATION_MODEL",
        "credential_secret": "DEEPSEEK_API_KEY",
        "endpoint_secret": "UNUSED_PROVIDER_ENDPOINT",
    },
    {
        "provider": "gemini",
        "model_variable": "GEMINI_QUALIFICATION_MODEL",
        "credential_secret": "GEMINI_API_KEY",
        "endpoint_secret": "UNUSED_PROVIDER_ENDPOINT",
    },
    {
        "provider": "huggingface",
        "model_variable": "HUGGINGFACE_QUALIFICATION_MODEL",
        "credential_secret": "HUGGINGFACE_API_KEY",
        "endpoint_secret": "UNUSED_PROVIDER_ENDPOINT",
    },
    {
        "provider": "ollama",
        "model_variable": "OLLAMA_QUALIFICATION_MODEL",
        "credential_secret": "UNUSED_PROVIDER_CREDENTIAL",
        "endpoint_secret": "OLLAMA_BASE_URL",
    },
    {
        "provider": "vllm",
        "model_variable": "VLLM_QUALIFICATION_MODEL",
        "credential_secret": "VLLM_API_KEY",
        "endpoint_secret": "VLLM_BASE_URL",
    },
)
PROVIDERS = tuple(config["provider"] for config in PROVIDER_CONFIGS)


class QualificationPlanError(ValueError):
    """The requested live-provider plan is malformed or unsupported."""


def parse_provider_set(value: str) -> list[str]:
    """Return a unique provider set in the checked-in canonical order."""

    requested = value.strip()
    if not requested:
        return []
    if requested == "all":
        return list(PROVIDERS)

    parsed: list[str] = []
    seen: set[str] = set()
    for raw_provider in requested.split(","):
        provider = raw_provider.strip()
        if not provider or PROVIDER_RE.fullmatch(provider) is None:
            raise QualificationPlanError(
                "providers must be a comma-separated list of lowercase provider IDs"
            )
        if provider not in PROVIDERS:
            raise QualificationPlanError(f"unsupported provider: {provider}")
        if provider in seen:
            raise QualificationPlanError(f"duplicate provider: {provider}")
        seen.add(provider)
        parsed.append(provider)

    return [provider for provider in PROVIDERS if provider in seen]


def build_plan(provider_set: str, commit: str) -> dict[str, object]:
    """Build the retained plan without treating configuration as live evidence."""

    if COMMIT_RE.fullmatch(commit) is None:
        raise QualificationPlanError(
            "source commit must be a lowercase 40-character SHA-1"
        )
    selected = parse_provider_set(provider_set)
    selected_set = set(selected)
    status = "ready" if selected else "not_run"
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "qualification_class": QUALIFICATION_CLASS,
        "status": status,
        "production_claim_allowed": False,
        "source": {"commit": commit},
        "selected_providers": selected,
        "unselected_providers": [
            provider for provider in PROVIDERS if provider not in selected_set
        ],
        "available_providers": list(PROVIDERS),
        "matrix": {
            "include": [
                dict(config)
                for config in PROVIDER_CONFIGS
                if config["provider"] in selected_set
            ]
        },
    }
    if not selected:
        report["reason"] = (
            "no live providers are enabled; configure the repository variable "
            "AGENTOS_LIVE_PROVIDER_SET or provide a workflow-dispatch provider set"
        )
    return report


def write_json(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def write_github_output(path: Path, report: dict[str, object]) -> None:
    selected = report["selected_providers"]
    assert isinstance(selected, list)
    with path.open("a", encoding="utf-8") as output:
        output.write(
            "providers="
            + json.dumps(selected, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        )
        output.write(
            "matrix="
            + json.dumps(
                report["matrix"], separators=(",", ":"), ensure_ascii=True
            )
            + "\n"
        )
        output.write(f"has_providers={'true' if selected else 'false'}\n")


def validate_catalog() -> None:
    if not PROVIDER_CONFIGS:
        raise QualificationPlanError("provider catalog must not be empty")
    if len(PROVIDERS) != len(set(PROVIDERS)):
        raise QualificationPlanError("provider catalog contains duplicates")
    required_keys = {
        "provider",
        "model_variable",
        "credential_secret",
        "endpoint_secret",
    }
    for config in PROVIDER_CONFIGS:
        if set(config) != required_keys:
            raise QualificationPlanError("provider configuration keys are incomplete")
        provider = config["provider"]
        if PROVIDER_RE.fullmatch(provider) is None:
            raise QualificationPlanError(
                f"provider catalog contains an invalid ID: {provider}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--providers", default="")
    parser.add_argument("--commit")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)

    try:
        validate_catalog()
        if args.validate:
            if any(
                value is not None
                for value in (args.commit, args.output, args.github_output)
            ) or args.providers:
                raise QualificationPlanError(
                    "--validate cannot be combined with plan output arguments"
                )
            print(
                f"validated live-provider plan schema v{SCHEMA_VERSION} "
                f"with {len(PROVIDERS)} providers"
            )
            return 0
        if args.commit is None or args.output is None:
            raise QualificationPlanError("--commit and --output are required")

        report = build_plan(args.providers, args.commit)
        write_json(args.output, report)
        if args.github_output is not None:
            write_github_output(args.github_output, report)
    except (QualificationPlanError, OSError) as error:
        print(f"live-provider qualification plan failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

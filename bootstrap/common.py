"""Shared helpers: sessions/profiles, tag config, CLI plumbing."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from string import Template
from typing import Any, Mapping

import boto3
import yaml
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

log = logging.getLogger("bootstrap")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_CONFIG = REPO_ROOT / "config" / "tags.yaml"

# Tag key every tool stamps on its resources so they can be found later.
TOOL_TAG_KEY = "bootstrap:tool"


class BootstrapError(Exception):
    """A user-facing error; printed without a traceback."""


# --------------------------------------------------------------------------- #
# Sessions
# --------------------------------------------------------------------------- #
def make_session(profile: str | None, region: str | None) -> boto3.Session:
    """Build a boto3 session from a named profile (or the default chain)."""
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
    except ProfileNotFound as exc:
        raise BootstrapError(str(exc)) from exc
    if not session.region_name:
        raise BootstrapError(
            "No region set. Pass --region or configure one for the profile."
        )
    return session


def caller_identity(session: boto3.Session) -> dict[str, str]:
    try:
        ident = session.client("sts").get_caller_identity()
    except NoCredentialsError as exc:
        raise BootstrapError(
            "No AWS credentials found. Pass --profile or configure credentials."
        ) from exc
    except ClientError as exc:
        raise BootstrapError(f"Unable to verify credentials: {exc}") from exc
    return {"account_id": ident["Account"], "arn": ident["Arn"]}


# --------------------------------------------------------------------------- #
# Tags
# --------------------------------------------------------------------------- #
class TagConfig:
    """Tags loaded from YAML: `common` merged with `resources.<type>`."""

    def __init__(self, data: Mapping[str, Any], context: Mapping[str, str] | None = None):
        self._common = _str_map(data.get("common") or {}, "common")
        self._resources = {
            rtype: _str_map(tags or {}, f"resources.{rtype}")
            for rtype, tags in (data.get("resources") or {}).items()
        }
        self.context: dict[str, str] = dict(context or {})

    @classmethod
    def load(cls, path: str | Path | None = None, context: Mapping[str, str] | None = None) -> "TagConfig":
        path = Path(path) if path else DEFAULT_TAGS_CONFIG
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except FileNotFoundError as exc:
            raise BootstrapError(f"Tag config not found: {path}") from exc
        except yaml.YAMLError as exc:
            raise BootstrapError(f"Invalid YAML in {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise BootstrapError(f"{path}: top level must be a mapping")
        return cls(data, context)

    def tags_for(self, resource_type: str, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        merged = {**self._common, **self._resources.get(resource_type, {}), **(extra or {})}
        return {k: Template(v).safe_substitute(self.context) for k, v in merged.items()}

    def tag_list(self, resource_type: str, extra: Mapping[str, str] | None = None) -> list[dict[str, str]]:
        return to_tag_list(self.tags_for(resource_type, extra))


def _str_map(value: Any, where: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise BootstrapError(f"Tag config section '{where}' must be a mapping")
    out = {}
    for k, v in value.items():
        if str(k).lower().startswith("aws:"):
            raise BootstrapError(f"Tag key '{k}' in '{where}': 'aws:' prefix is reserved")
        out[str(k)] = "" if v is None else str(v)
    return out


def to_tag_list(tags: Mapping[str, str]) -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in tags.items()]


def tag_value(tags: list[dict[str, str]] | None, key: str) -> str | None:
    for t in tags or []:
        if t["Key"] == key:
            return t["Value"]
    return None


# --------------------------------------------------------------------------- #
# CLI plumbing
# --------------------------------------------------------------------------- #
def add_common_args(parser: argparse.ArgumentParser) -> None:
    g = parser.add_argument_group("AWS")
    g.add_argument("--profile", "-p", help="AWS named profile (default: credential chain / AWS_PROFILE)")
    g.add_argument("--region", "-r", help="AWS region (default: profile's region / AWS_REGION)")
    g.add_argument("--tags-config", default=None,
                   help=f"Tag config YAML (default: {DEFAULT_TAGS_CONFIG.relative_to(REPO_ROOT)})")
    g.add_argument("--verbose", "-v", action="store_true", help="Debug logging")


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    if not verbose:
        for noisy in ("botocore", "boto3", "urllib3"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


def run_cli(main_fn, argv=None) -> int:
    """Run a tool's main(), turning BootstrapError/ClientError into exit codes."""
    try:
        return main_fn(argv) or 0
    except BootstrapError as exc:
        log.error("%s", exc)
        return 2
    except ClientError as exc:
        log.error("AWS error: %s", exc)
        return 1
    except KeyboardInterrupt:
        return 130


def confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise BootstrapError("Refusing to proceed without a TTY; pass --yes to confirm.")
    return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")

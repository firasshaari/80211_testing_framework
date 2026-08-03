"""Vendored uCentral examples: loading, normalizing, categorizing, inspecting."""
from framework.examples.catalog import EXAMPLES, Area, Example, Mode, Requirement, get
from framework.examples.loader import load_example, parse_ucentral_json
from framework.examples.normalize import normalize_config, set_strict

__all__ = [
    "Area", "Example", "Mode", "Requirement", "EXAMPLES", "get",
    "load_example", "parse_ucentral_json", "normalize_config", "set_strict",
]

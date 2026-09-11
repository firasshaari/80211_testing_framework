"""Bench Console — a self-service web UI in front of the regression framework.

Everything here *drives* the framework; nothing here reimplements it. Runs are
started by spawning the same pytest entry point a person would type by hand, and
the probe/plan/catalog APIs are imported and called directly. If a behaviour
belongs to testing an AP, it lives in ``framework/``; if it belongs to letting a
human ask for that test and read the answer, it lives here.
"""
__version__ = "0.1.0"

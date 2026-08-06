"""
Loads a .env file (if present) into the process environment so that
GROQ_API_KEY / ANTHROPIC_API_KEY / etc. don't have to be exported by
hand in every terminal session.

This is called only from entry-point scripts (cli.py, examples/), never
from library modules -- library code should keep reading credentials
via `os.environ` directly (see llm/groq_provider.py etc.), so that
importing forge as a library never has hidden side effects on
the caller's environment.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def load_env(dotenv_path: str | Path | None = None) -> None:
    """
    Load key=value pairs from a .env file into os.environ, if
    python-dotenv is installed and the file exists. Silently does
    nothing otherwise (e.g. in CI, or if the user prefers exporting
    variables directly) -- this is a convenience, not a requirement.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        logger.debug("python-dotenv not installed; skipping .env loading. "
                      "Install with `pip install python-dotenv` or export "
                      "environment variables directly.")
        return

    path = Path(dotenv_path) if dotenv_path else Path(".env")
    if path.exists():
        load_dotenv(dotenv_path=path)
        logger.info("Loaded environment variables from %s", path)
    else:
        logger.debug("No .env file found at %s; relying on already-exported "
                      "environment variables.", path)

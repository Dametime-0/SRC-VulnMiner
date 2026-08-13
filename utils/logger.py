"""
Logger utility for the SRC Vulnerability Mining Agent.

Provides structured, colored console output and file logging.
Supports module-specific loggers with consistent formatting.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

# ANSI color codes for terminal output
COLORS = {
    "DEBUG": "\033[36m",     # Cyan
    "INFO": "\033[32m",      # Green
    "WARNING": "\033[33m",   # Yellow
    "ERROR": "\033[31m",     # Red
    "CRITICAL": "\033[35m",  # Magenta
    "RESET": "\033[0m",
}

# Log levels mapped to symbols for compact display
LEVEL_SYMBOLS = {
    "DEBUG": "·",
    "INFO": "✓",
    "WARNING": "⚠",
    "ERROR": "✗",
    "CRITICAL": "‼",
}


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter that adds color and symbols to console output.
    File output remains plain text for machine readability.
    """

    def __init__(self, use_color: bool = True):
        super().__init__(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        # Add symbol
        symbol = LEVEL_SYMBOLS.get(record.levelname, "·")
        record.symbol = symbol

        if self.use_color:
            color = COLORS.get(record.levelname, "")
            reset = COLORS["RESET"]
            record.levelname = f"{color}{record.levelname}{reset}"
            record.msg = f"{color}{symbol}{reset} {record.msg}"

        return super().format(record)


class MetricsLogHandler(logging.Handler):
    """
    Special handler that captures log events for metrics tracking.
    Counts warnings (potential issues) and errors (failures) per module.
    """

    def __init__(self):
        super().__init__()
        self.warning_count = 0
        self.error_count = 0
        self.module_counts: dict = {}

    def emit(self, record: logging.LogRecord) -> None:
        module = record.name
        if module not in self.module_counts:
            self.module_counts[module] = {"warnings": 0, "errors": 0}

        if record.levelno >= logging.ERROR:
            self.error_count += 1
            self.module_counts[module]["errors"] += 1
        elif record.levelno >= logging.WARNING:
            self.warning_count += 1
            self.module_counts[module]["warnings"] += 1

    def get_stats(self) -> dict:
        return {
            "total_warnings": self.warning_count,
            "total_errors": self.error_count,
            "by_module": self.module_counts,
        }


# Global registry of loggers
_loggers: dict = {}
_metrics_handler: Optional[MetricsLogHandler] = None


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    """
    Get or create a named logger with consistent configuration.

    Args:
        name: Module name (e.g., "agent.task_parser")
        level: Log level (DEBUG, INFO, WARNING, ERROR)

    Returns:
        Configured logger instance

    Example:
        >>> logger = get_logger("agent.analyzer")
        >>> logger.info("Starting code analysis...")
        >>> logger.warning("Suspicious pattern found at low confidence")
    """
    global _loggers, _metrics_handler

    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    # Console handler (colored)
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(ColoredFormatter(use_color=sys.stderr.isatty()))
    console.setLevel(logging.DEBUG)
    logger.addHandler(console)

    # File handler (plain text)
    log_dir = Path("output")
    log_dir.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(
        log_dir / f"agent_{datetime.now():%Y%m%d}.log",
        encoding="utf-8",
    )
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    # Metrics handler (tracks warnings/errors)
    if _metrics_handler is None:
        _metrics_handler = MetricsLogHandler()
    logger.addHandler(_metrics_handler)

    _loggers[name] = logger
    return logger


def get_metrics_handler() -> MetricsLogHandler:
    """Get the global metrics log handler for stats reporting."""
    global _metrics_handler
    if _metrics_handler is None:
        _metrics_handler = MetricsLogHandler()
    return _metrics_handler

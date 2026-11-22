"""Modular agentic attack & Red-Hat detection suite."""

from .base import BaseDetector, DetectorContext
from .registry import DetectorRegistry

__all__ = ["BaseDetector", "DetectorContext", "DetectorRegistry"]

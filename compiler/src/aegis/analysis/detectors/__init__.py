"""Detector registry -- one module per weakness class."""
from __future__ import annotations

from .base import Detector, DetectorRegistry
from .cwe_078_command import CommandInjectionDetector
from .cwe_120_overflow import BufferOverflowDetector
from .cwe_134_format import FormatStringDetector
from .cwe_401_leak import MemoryLeakDetector
from .cwe_416_uaf import DoubleFreeDetector, UseAfterFreeDetector
from .cwe_476_nullderef import NullDereferenceDetector

#: Detectors driven by the taint analysis.
TAINT_DETECTORS = [
    CommandInjectionDetector(),
    BufferOverflowDetector(),
    FormatStringDetector(),
]

#: Detectors driven by the heap state machine.
MEMORY_DETECTORS = [
    NullDereferenceDetector(),
    UseAfterFreeDetector(),
    DoubleFreeDetector(),
    MemoryLeakDetector(),
]

DEFAULT_REGISTRY = DetectorRegistry(TAINT_DETECTORS + MEMORY_DETECTORS)

__all__ = [
    "Detector",
    "DetectorRegistry",
    "DEFAULT_REGISTRY",
    "TAINT_DETECTORS",
    "MEMORY_DETECTORS",
]

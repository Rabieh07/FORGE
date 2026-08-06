"""
Core data model for the memory forensics knowledge graph framework.

This module defines the standardized intermediate representation used
in Phase 2 (Artifact Normalization) and the node/edge/behavior types
used in Phase 3 (Knowledge Graph Construction) and Phase 4 (Behavior
Inference). Every object defined here is JSON-serializable so that
graph subsets can be safely passed to an LLM (Phase 5/6) without ever
exposing raw memory bytes or unvalidated tool output.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------

class ArtifactType(str, Enum):
    """Layer-1 observable artifact / node types (Section III.D)."""
    PROCESS = "Process"
    THREAD = "Thread"
    DLL = "DLL"
    REGISTRY_KEY = "RegistryKey"
    FILE = "File"
    SOCKET = "Socket"
    SERVICE = "Service"
    DRIVER = "Driver"
    MEMORY_REGION = "MemoryRegion"
    HANDLE = "Handle"
    USER = "User"
    CREDENTIAL = "Credential"
    MUTEX = "Mutex"


class EdgeType(str, Enum):
    """Layer-1 relationship / edge types (Section III.D)."""
    SPAWNS = "SPAWNS"
    LOADS = "LOADS"
    CONNECTS_TO = "CONNECTS_TO"
    OPENS = "OPENS"
    WRITES = "WRITES"
    OWNS = "OWNS"
    CREATES = "CREATES"
    INJECTS = "INJECTS"
    ACCESSES = "ACCESSES"
    MODIFIES = "MODIFIES"
    ALLOCATES = "ALLOCATES"  # extension used in the RWX-memory example


class BehaviorConcept(str, Enum):
    """Layer-3 behavioral concepts (Section III.E)."""
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    DEFENSE_EVASION = "Defense Evasion"
    COMMAND_AND_CONTROL = "Command and Control"
    CODE_INJECTION = "Code Injection"
    PRIVILEGE_ESCALATION = "Privilege Escalation"


EVIDENCE_FOR = "evidence_for"  # Layer-1/2 -> Layer-3 provenance edge label


# ---------------------------------------------------------------------
# Phase 2: normalized artifact object
# ---------------------------------------------------------------------

@dataclass
class Artifact:
    """
    Standardized intermediate representation for a single extracted
    memory artifact (Section III.C). Every artifact produced by the
    normalizer, regardless of source Volatility plugin, has this shape.
    """
    artifact_type: ArtifactType
    attributes: dict[str, Any]
    source_plugin: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: Optional[str] = None
    confidence: float = 1.0
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["artifact_type"] = self.artifact_type.value
        return d


@dataclass
class Relationship:
    """
    A normalized relationship between two artifacts, prior to graph
    insertion. Distinct from a graph edge object so that the
    normalizer can remain agnostic to the graph backend (NetworkX,
    Neo4j, etc.) used in Phase 3.
    """
    source_id: str
    target_id: str
    edge_type: EdgeType
    attributes: dict[str, Any] = field(default_factory=dict)
    source_plugin: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["edge_type"] = self.edge_type.value
        return d


# ---------------------------------------------------------------------
# Phase 4: inferred behavior object
# ---------------------------------------------------------------------

@dataclass
class InferredBehavior:
    """
    A behavioral concept node created by the Phase 4 inference engine.
    Every field here exists to satisfy the explainability and evidence
    traceability requirements described in Section III.H: nothing here
    is guessed by the LLM, it is entirely produced by the rule engine.
    """
    behavior: BehaviorConcept
    rule_id: str
    supporting_artifact_ids: list[str]
    supporting_relationship_ids: list[str]
    confidence: float
    explanation_path: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["behavior"] = self.behavior.value
        return d

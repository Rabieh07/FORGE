"""
FORGE (Forensic Ontology-based Reasoning over Graph Evidence): an
explainable knowledge-graph framework for LLM-assisted memory
forensics.

Pipeline phases (see paper Section III):
    1. Memory Artifact Extraction  -> volatility_adapter.py
    2. Artifact Normalization      -> normalizer.py
    3. Knowledge Graph Construction -> graph_builder.py
    4. Behavior Inference (FBO)    -> inference.py, rules/evidence_patterns.yaml
    5/6. LLM-Assisted Reasoning / Report Generation -> llm/
"""

__version__ = "0.1.0"

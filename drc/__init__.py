"""drc — Dependency Resolution Consistency checker (prototype).

Pipeline: frontend (structured parsing) -> intent (evidence) -> rto/contexts (test generation)
-> resolvers (real pip / uv execution) -> oracle (artifact identity diff) -> minimize -> report -> triage.
"""
__version__ = "0.1.0"

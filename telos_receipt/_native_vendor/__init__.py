"""MIT-licensed native verifier adapters; see package NOTICE.

TCAS G4/G8 complexity justification: verify_native_v2.assess_bytes (CC 33)
and verify_native_v2._validate (CC 28) retain the upstream-derived verifier's
control flow byte-identical to the pinned artifact. Its SHA-256 is
98bfab078eb85fde1f740c8c7e165965f02d6cdc38257b5e0b93b404b1f6835d;
the adapter SHA-256 is
6eb37e9f8018ff98a6d4546f707de17cb64b53038a6d7311bf7ba89ab79e24bf.

The source is the package-only verifier supplied for this release, adapted
from TELOS-Labs-AI/hermes-agent as described in NOTICE. assess_bytes binds
bounded rows, hashes, predecessor links and fail-closed aggregate status;
_validate enforces native schema, JSON bounds and proof shape together.
Refactoring either function would change the source pin and invalidate the
artifact-bound verification evidence. Retaining this reviewed artifact is
preferable to duplicating or rearranging its security-sensitive branches.
The package wrapper provides the public API; tests and single-guard sabotage
exercise the retained controls without editing these pinned source files.
"""

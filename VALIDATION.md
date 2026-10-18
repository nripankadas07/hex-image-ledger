# Validation

Reproduce mode changes, sparse gaps, checksum errors, identical/conflicting overlaps, address-sensitive hashes, uncovered entries and overflow rejection.

16 behavior test methods plus installed CLI success/finding/malformed cases and byte preservation. CI executes Linux/Python3.10,3.12,3.14 unit, compilation, wheel and clean-venv installed checks. Configured CI alone does not prove success; inspect current Actions results. PREPARATION.json records executed Linux/Python3.12 preparation. Production workloads and other platforms remain untested. No performance benchmark.

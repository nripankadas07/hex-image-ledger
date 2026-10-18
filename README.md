# hex-image-ledger

Explain Intel HEX sparse address coverage, gaps, entry context and every overlapping write without flashing.

For: Firmware maintainers reviewing a HEX handoff before device programming. A checksum-valid image can still contain contradictory writes or sparse holes; choosing a last writer hides evidence.

## Quickstart

Python3.10+; no runtime packages/network. Building the wheel needs setuptools from the normal Python registry.

```sh
git clone https://github.com/nripankadas07/hex-image-ledger.git
cd hex-image-ledger
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/hex-image-ledger example.hex
```

Exit 0: six unique bytes occupy two ranges at 0x08000000..04 and 0x08000008..0A; the interior gap is four bytes. No hole is filled.

Windows equivalents use `.venv\Scripts\python.exe` and `.venv\Scripts\hex-image-ledger.exe`; Windows/macOS have not been executed by this release's Linux CI.

## Contract

ASCII Intel HEX records00/01/02/03/04/05 with actual byte count and checksum validation. Segment and linear base changes affect subsequent records. Ranges use exclusive ends. All overlaps, including identical repeats, are findings; conflicting values have no selected winner. The unambiguous sparse-map SHA256 is domain-separated and hashes sorted four-byte big-endian address plus byte, excluding conflicting cells. Entry records are unique; raw numerical coverage is checked without CPU/A20/Thumb interpretation. EOF is mandatory and final.

Report JSON goes to stdout. Exit0 means a valid report without documented findings, exit1 a valid report with findings, exit2 invalid/unsupported input or I/O failure with stderr and no partial report. This is a bounded read-only inspection tool; the optional example generator only creates an explicitly named new file.

## Limits

1 MiB,8192 records,262144 data-byte events,32-bit address space. No record may wrap its16-bit offset. Overlap evidence is capped at256 addresses with an omitted count. Gaps are informational. No conversion, winner policy, filling, binary output, flashing or hardware verification.

## Verify

```sh
python3 -m unittest -v test_behavior
python3 -m compileall -q .
python3 -m pip wheel --no-deps --wheel-dir dist .
python3 -m venv /tmp/hex-image-ledger-check
/tmp/hex-image-ledger-check/bin/python -m pip install --no-deps dist/*.whl
python3 verify_installed.py /tmp/hex-image-ledger-check/bin/python
```

Installed-command checks run outside the checkout. See [validation](VALIDATION.md), [research](RESEARCH.md), [contributing](CONTRIBUTING.md), [support](SUPPORT.md), [security](SECURITY.md) and [license](LICENSE).

Original implementation, prose and invented fixtures developed with AI assistance. MIT license. No verified production adoption or performance-superiority claim.

# Contributing

Use Python 3.12+ and install `requirements.txt`. Run the offline test suite:

```sh
python -m unittest discover -s tests -v
python scripts/check_docs.py
```

Tests for external providers should mock HTTP responses, cover partial results
and rate limits, and check that error reports redact API keys. Distinguish live
checks from offline tests in your report. Use mocked credentials in CI.

Capture changes must preserve evidence labels and avoid assigning ambiguous UDP
traffic to one process. Test the driver-missing GUI state without opening a
window. Run live capture checks on a Windows host where you have permission to
observe the application and network.

For portable changes, follow [the build guide](docs/building.md) and run the
relocated ZIP test. Keep Npcap binaries and local reports out of the public
package. Preserve dependency licenses and source references.

Use one focused change per pull request and state the validation performed.
Contributions use the project's Apache-2.0 license.

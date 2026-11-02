# Portable builds and releases

## Build inputs

Build the Windows x64 edition on Windows with 64-bit Python 3.12+ including Tk,
7-Zip and access to the package/dependency download servers. The GitHub workflow
uses Python 3.13 on `windows-2025`.

`packaging/dependencies.json` pins the Wireshark installer and corresponding
source archive by version and SHA-256. The builder verifies both downloads. It
copies Python from the interpreter running the build, including Tk and pinned
application packages. The runtime manifest records their actual versions and
file hashes without workstation paths.

```powershell
python -m pip install -r requirements.txt pefile==2024.8.26
python scripts/fetch_dependencies.py
python scripts/build_runtime.py --wireshark build/wireshark
python scripts/package_portable.py
python tests/portable_smoke.py
```

You can pass an existing matching Wireshark installation to `--wireshark` for an
offline runtime build. The output directory must be empty. Choose a new
`--output` directory when rebuilding; the builder does not remove an existing
runtime tree.

## Artifacts and checks

The package contains application code, Python/Tk, dependencies, TShark, protocol
data, the Public Suffix List, licenses and documentation. It excludes Npcap
binaries and installers, development environments, reports and credentials.
Install Npcap from its official site when capture is needed.

`dist/NetLens-win-x64.zip.sha256` records the ZIP checksum. The ZIP uses stable
timestamps for identical packaging inputs. Different Python builds or dependency
inputs produce different runtime manifests and archives.

The portable smoke test extracts into a new path, restricts `PATH` to Windows
system tools and checks bundled Python, unit tests, Tcl and TShark. It does not
claim live capture or authenticated provider coverage. Run capture and provider
integration checks in an authorized environment with the required driver and
accounts.

## GitHub Releases

Push a version tag such as `1.0-a1b2c3d` to run `.github/workflows/release.yml`. The
workflow tests the application, downloads pinned inputs, builds the runtime,
packages the ZIP and tests the relocated archive. It publishes the ZIP,
checksum and matching Wireshark source archive in the tag's release.

Read the base version from `VERSION` and use the first seven characters of the
tagged commit SHA after the hyphen. The packager records that SHA in the ZIP.
NetLens shows the version at the lower left and links it to the matching tag.
Use `python -m netlens --version` to print it from the command line. For builds
without Git metadata, set `SOURCE_REVISION` to the full source commit SHA.

Choose Русский or English at the top of the window. NetLens saves the choice in
`preferences.json` beside the application. For the CLI, place `--language en`
or `--language ru` before the subcommand. `NETLENS_LANGUAGE` overrides the saved
choice; otherwise NetLens starts with your system language, using English for
languages other than Russian.

A manual workflow run creates downloadable Actions artifacts without publishing
a release. Rerunning a tag workflow replaces that tag's assets. The workflow
uses the repository's `GITHUB_TOKEN` with Contents write permission for release
publication; it does not require a personal access token.

When updating Wireshark, update the version, URLs and checksums together. Review
dependency licenses and verify the public archive policy before tagging. Keep
the corresponding source archive available alongside the binary distribution.

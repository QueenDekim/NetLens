# NetLens

NetLens discovers domain names, IP addresses and BGP prefixes, and records the
network destinations of a selected Windows application. It includes a Russian
desktop interface and a command-line interface.

## Windows portable edition

Download `NetLens-win-x64.zip` and its SHA-256 file from
[Releases](https://github.com/QueenDekim/NetLens/releases). Extract the complete
archive and open `NetLens.cmd`. The archive includes Python, Tk, dependencies and
TShark; you do not need separate installations of those components.

Application capture requires the [Npcap driver](https://npcap.com/#download).
NetLens disables capture and interface enumeration when it cannot find the
driver. The capture tab provides a download button and an installation recheck.
Domain discovery, DNS, redirects, copy and export remain available. Install Npcap
with administrator rights; its access policy may also require you to run capture
as an administrator. NetLens does not install the driver or change services.

## Capabilities

- Subdomain discovery through selectable Certificate Transparency providers,
  with fallback and attempt history.
- Registrable-domain normalization using a bundled Public Suffix List.
- HTTP and HTML redirect discovery, A/AAAA/CNAME lookup and BGP enrichment.
- EXE capture with child-process tracking and evidence for observed destinations.
- Complete domain/IP copy lists and JSON, CSV and text exports.

CT data does not contain every subdomain. Shared certificates and DNS candidates
provide leads, not proof that two names share an owner or that an application
connected to a name. Reports retain source labels and limitations.

## Run from source

Use Python 3.12+ and install the application dependencies:

```sh
git clone https://github.com/QueenDekim/NetLens.git
cd NetLens
python -m venv .venv
```

Activate the environment for your shell, then run:

```sh
python -m pip install -r requirements.txt
python -m netlens discover example.com --output reports/example
python -m netlens gui
```

The Windows GUI and EXE capture target Windows 10/11 x64. Domain discovery and
the CLI can run on other platforms with the same Python dependencies. For
source-based Windows capture, install TShark or set `NETLENS_TSHARK` to its path.

## Documentation and development

Read the [documentation](docs/README.md) for discovery, capture attribution,
provider keys, export formats and portable builds. The
[release workflow](.github/workflows/release.yml) builds and tests the Windows ZIP
for a `v*` tag and uploads it to GitHub Releases. Manual runs produce build
artifacts without creating a release.

[Xray Gateway](https://github.com/QueenDekim/XRay-gateway) can import a NetLens
`ips.txt` export. The repositories have independent runtimes and release cycles.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Project code
uses [Apache-2.0](LICENSE); bundled components retain their
[own licenses](THIRD_PARTY_NOTICES.md).

# Releases and version numbers

Use `MAJOR.MINOR.PATCH-<seven-character commit SHA>` for tags and displayed
versions. Each repository has its own version sequence.

Increase major for incompatible configuration or API changes. Increase minor
for new capabilities, such as new transports, subscription import or account
controls. Increase patch for fixes, interface corrections and packaging changes.
A minor release resets patch to zero; a major release resets minor and patch.

Before committing a release, update VERSION:

```sh
python scripts/bump_version.py minor
# For a fix, use patch; for incompatible changes, use major.
```

Update CHANGELOG.md and run the repository checks. Commit the changes before
creating the tag so its suffix identifies the released source:

```sh
python scripts/check_version.py
git add VERSION CHANGELOG.md
git commit -m "Prepare release"
version=$(cat VERSION)
revision=$(git rev-parse --short=7 HEAD)
tag="$version-$revision"
git tag -a "$tag" -m "Release $version"
python scripts/check_version.py --tag "$tag"
git push --atomic origin main "$tag"
```

The release check rejects a tag that disagrees with VERSION, a mismatched SHA,
or another tag that already uses the same version number. CI fetches tags
before running this check. Container and ZIP metadata retain the version and
revision when Git is absent at runtime.

The historical mappings in release-history.json cover the tag correction.
CHANGELOG.md records the changes behind those versions. Historical tags point
to the original commits; the correction does not rewrite Git history.

A tagged release builds the Windows ZIP, checks the relocated runtime, and
publishes the ZIP, checksum and corresponding Wireshark source archive.

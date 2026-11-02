# Third-party notices

NetLens application code uses Apache-2.0. Components in a portable distribution
retain the following licenses and their original notices.

| Component | License and source |
| --- | --- |
| Python and Tk | PSF license and bundled component notices in `third-party/python/LICENSE.txt` and the Tcl/Tk files |
| dnspython | ISC license in the package metadata |
| psutil | BSD-3-Clause license in the package metadata |
| TShark, Dumpcap and Wireshark data | GPL-2.0-or-later and component-specific licenses; see `third-party/wireshark/COPYING.txt` and included notices |
| Public Suffix List | MPL-2.0; the bundled snapshot retains its source and notices |

The Wireshark version, source URL and SHA-256 appear in
`packaging/dependencies.json` and `third-party/wireshark/SOURCE.txt` in the ZIP.
Release assets include the corresponding Wireshark source archive. Dependencies
used by Wireshark retain their upstream licenses.

Npcap is an external prerequisite for application capture. The public NetLens
archive excludes its driver, DLLs, helper executable and installer. Obtain it
from [Npcap](https://npcap.com/#download) under its own license. Npcap's
[redistribution terms](https://npcap.com/oem/redist) require separate permission
for bundling it in another product.

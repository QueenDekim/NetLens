Public Suffix List

Source: https://publicsuffix.org/list/public_suffix_list.dat
Snapshot: 2026-10-31_14-17-28_UTC
Commit: 73f8cc701c084fe07d888ec552b2f0b53281a674

The original file is bundled unchanged, with its MPL 2.0 notice and source URL.
Search-root lookup uses the ICANN section. PRIVATE rules remain available for
tenant-level grouping but do not restrict CT analysis of parent domains such as
googleapis.com.
To refresh, replace public_suffix_list.dat from the source URL and rebuild the
third-party manifest and portable archive using scripts/build_portable.py and
scripts/package_portable.py. No refresh is performed when the application runs.

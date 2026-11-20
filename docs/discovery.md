# Domain discovery

Enter a hostname on the discovery tab. NetLens searches from its registrable
domain when CT is enabled: `a.b.example.co.uk` uses `example.co.uk`. It preserves
the input name in the report. Search-root calculation uses the ICANN section of
the bundled Public Suffix List and works offline. PRIVATE entries describe hosted
tenant boundaries and do not restrict the search scope: `googleapis.com`,
`oauth2.googleapis.com` and `www.googleapis.com` all search `googleapis.com`.
Likewise, `www.project.github.io` searches `github.io`; `co.uk` remains a public
registry suffix, so `a.example.co.uk` searches `example.co.uk`. The report records
`root_policy: psl_icann` when CT is enabled. The same policy applies to redirect
roots. The list also retains PRIVATE rules for callers that explicitly need
tenant-level domain grouping.

NetLens queries the selected CT provider, follows HTTP/HTML redirects, resolves
A/AAAA and CNAME records, and can request BGP/ASN metadata from RIPEstat. These
lookups require network access. Root-domain calculation and local report handling
do not require a service.

```sh
python -m netlens discover www.example.com --limit 200 --output reports/example
python -m netlens discover www.example.com --no-ct --no-redirects --no-networks
```

`--no-ct` keeps DNS lookup scoped to the input name. Redirect discovery remains
enabled unless you pass `--no-redirects`. `--include-related` also resolves names
from shared-certificate candidates. Review those candidates before using them
as a routing policy.

## Redirects

The scanner checks HTTP, HTTPS and the root/`www` forms. It follows HTTP redirect
status codes, `Refresh` headers and HTML `meta refresh`, including relative URLs.
It records intermediate hosts and direct IP targets. It does not execute
JavaScript or authenticate to websites.

The scanner limits a chain to ten hops, a discovery run to 32 redirect requests
and a 30-second redirect budget. It reads up to 64 KiB of initial HTML. CT
expansion covers up to four additional redirect roots. The JSON report records
cycles, TLS failures and unavailable targets without discarding other results.

The domain limit favors the input name, its root and immediate redirect targets.
DNS addresses can change after the scan. A BGP prefix describes a routed network;
it can cover other customers and should not be treated as one site's address list.

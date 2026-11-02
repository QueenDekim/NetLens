# Reports and exports

The GUI saves each completed or stopped task under `reports/`. Use Export to
choose another directory. In the CLI, pass `--output PATH` to set it.

| File            | Contents                                                     |
| --------------- | ------------------------------------------------------------ |
| `report.json`   | Structured results, evidence, warnings and provider attempts |
| `domains.txt`   | Deduplicated domain names                                    |
| `ips.txt`       | Deduplicated IPv4 and IPv6 addresses                         |
| `subnets.txt`   | BGP prefixes found during enrichment                         |
| `endpoints.csv` | Tabular domain/address or endpoint records                   |

Copy Domains and Copy IPs use the complete deduplicated report lists. They do
not depend on the current table scroll position. The GUI provides horizontal
and vertical scrollbars for the results table.

Discovery reports retain `input_domain`, `root`, `scope_expanded`, `ct`,
`ct_by_root`, `redirect_roots` and redirect chains when those features run.
Capture reports retain process IDs, ports, transports, observation times and
hostname evidence. Treat IPs and BGP prefixes as separate export types.

Reports can reveal application use, visited hosts and process paths. Review a
report before sharing it or attaching it to an issue. NetLens excludes API keys
from its report fields, but unrelated application metadata can still be private.

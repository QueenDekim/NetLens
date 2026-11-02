# Certificate Transparency providers

Choose a provider in the GUI or pass `--ct-provider` in the CLI. Enable fallback
to try another provider after an unavailable, limited or invalid response.

| CLI name | Provider | Optional environment key |
| --- | --- | --- |
| `ctlogs.dev` | [ctlogs.dev](https://ctlogs.dev/) | `CTLOGS_API_KEY` |
| `sslboard` | [SSLBoard](https://sslboard.com/) | `SSLBOARD_API_KEY` |
| `certspotter` | [Cert Spotter](https://sslmate.com/certspotter/) | `CERTSPOTTER_API_KEY` |
| `merklemap` | [Merklemap](https://www.merklemap.com/) | `MERKLEMAP_API_KEY` |
| `enterno` | [Enterno](https://enterno.io/) | `ENTERNO_API_KEY` |

The Merklemap and Enterno adapters require a key. Provider access, pricing and
history windows depend on the service and your account. Enterno can return
passive-source data; the report uses a distinct evidence label for it.

```sh
python -m netlens discover example.com --ct-provider sslboard
python -m netlens discover example.com --ct-provider ctlogs.dev --no-ct-fallback
```

Auto mode tries ctlogs.dev first, followed by SSLBoard, Cert Spotter, Merklemap
and Enterno. A selected provider runs first, followed by the remaining providers
in that order. Successful empty responses finish the search; a local user limit
does not consume another provider's quota.

Fallback covers connection errors, timeouts, HTTP 429, authorization failures,
service limits and malformed responses. The process observes `Retry-After` and
keeps partial results from failed attempts. `ct.attempts` records the order,
status and limits of each attempt. Coverage differs between providers.

Set keys through the GUI's API-key dialog or your process environment. NetLens
keeps GUI keys in memory for the current session and excludes them from reports.
Avoid putting keys in command-line arguments, screenshots or issue reports.

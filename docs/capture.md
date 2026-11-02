# Windows application capture

## Dependencies

The portable edition includes TShark. Application capture also needs an installed
[Npcap driver](https://npcap.com/#download). The capture tab checks for its files
and service without changing the installation. It disables capture and network
interface enumeration if the driver is missing or cannot be checked.

Use **Download Npcap** to open the official download page. Install the driver,
then choose **Check installation** in NetLens. Other discovery and report
functions remain available while capture is disabled. If Npcap restricts access
to administrators, launch NetLens with the corresponding rights.

## Run a capture

1. Select the application's EXE and the active network interface.
2. Set the duration and choose whether to include child processes.
3. Start capture and perform the actions you want to observe.
4. Stop capture or wait for the duration, then inspect the report.

NetLens starts TShark before launching the application. Capture termination
leaves the application running. Attach mode selects existing processes with the
same EXE path; use it for applications that hand work to an existing instance.

```powershell
python -m netlens interfaces
python -m netlens capture --exe 'C:\Apps\Example\app.exe' -i 1 --seconds 60 --output reports/app
python -m netlens capture --exe 'C:\Apps\Example\app.exe' -i 1 --attach --seconds 30
```

Choose a VPN interface when the application's traffic traverses a VPN. Multiple
interfaces can observe the same packet, so cross-interface totals can contain
duplicates. Encrypted DNS, TLS ECH and connections opened between socket samples
can hide names or weaken attribution.

## Evidence

| Evidence                      | Interpretation                                             |
| ----------------------------- | ---------------------------------------------------------- |
| `socket_table`                | A process socket had the remote address                    |
| `tcp_tuple_sampled`           | A packet matched a sampled TCP connection                  |
| `udp_unique_bind_sampled`     | A packet matched a UDP binding without a competing owner   |
| `tls_sni`, `http_host`        | An attributed packet exposed a hostname                    |
| `dns_query_on_process_socket` | The process queried a name through its own DNS socket      |
| `dns_candidates`              | Nearby DNS traffic suggested a hostname for an observed IP |

An observed DNS query does not prove a connection to that name. A socket address
does not prove that an application received a response. Retain the evidence
labels when you reuse capture results.

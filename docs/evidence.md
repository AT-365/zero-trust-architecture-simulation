# Validation evidence

## Reproducible simulation result

Running `python src/zero_trust_simulation.py` produces:

```text
Zero Trust simulation complete
Total access requests: 13
Allowed requests: 3
Denied requests: 10
Policy tests passed: 13/13
Alerts generated: 13
```

The generated files in `results/` allow each claim to be checked:

- `test_summary.csv` confirms that all expected and actual decisions match.
- `access_log.csv` preserves the controls that caused each denial.
- `alerts.csv` records ten denial alerts plus three repeated-denial escalations.

## Cloud and network lab evidence

The accompanying academic lab used an Azure Ubuntu virtual machine. SSH was restricted to one trusted `/32` source, controlled traffic was generated against a localhost HTTP resource, and packet behavior was captured and inspected with `tcpdump`. The lab also used `nmap` for controlled validation.

The public repository includes selected evidence that does not expose live infrastructure details:

- [`../evidence/http_server.log`](../evidence/http_server.log) records successful localhost HTTP requests.
- [`../evidence/zt_capture.pcap`](../evidence/zt_capture.pcap) contains the small loopback-only packet capture used in the lab.
- [`../portfolio/Autenia_Murray_Zero_Trust_Screenshot_Evidence.pdf`](../portfolio/Autenia_Murray_Zero_Trust_Screenshot_Evidence.pdf) contains redacted Azure, Ubuntu, packet-capture, simulation, and CSV screenshots.
- [`../portfolio/Autenia_Murray_Zero_Trust_Live_Demo.mp4`](../portfolio/Autenia_Murray_Zero_Trust_Live_Demo.mp4) shows the simulation run and explains the generated evidence.

Credentials, SSH keys, account identifiers, and real public IP addresses remain excluded.

## Accuracy boundary

The repository demonstrates a policy decision and monitoring prototype. It does not claim production deployment, live identity-provider integration, endpoint-management integration, or SIEM operation.

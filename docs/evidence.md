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

The accompanying academic lab used an Azure Ubuntu virtual machine. SSH was restricted to one trusted `/32` source, controlled traffic was generated, and packet behavior was inspected with `tcpdump` and Wireshark. The lab also used `nmap` for controlled validation.

The raw packet capture and cloud screenshots are intentionally omitted from this public portfolio repository. That keeps infrastructure details private while the executable policy code and synthetic verification evidence remain directly inspectable.

## Accuracy boundary

The repository demonstrates a policy decision and monitoring prototype. It does not claim production deployment, live identity-provider integration, endpoint-management integration, or SIEM operation.


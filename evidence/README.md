# Network evidence

This directory contains the small network artifacts used in the controlled Azure Ubuntu lab.

## Files

- `http_server.log` records four successful requests to the protected local HTTP resource.
- `zt_capture.pcap` contains loopback traffic generated against `127.0.0.1:8080` and captured with `tcpdump`.

The files contain no credentials, SSH keys, cloud account identifiers, or real public IP addresses. The packet capture is included as technical evidence and can be inspected with a compatible packet-analysis tool.

For the visual evidence and explanation, see the [screenshot evidence packet](../portfolio/Autenia_Murray_Zero_Trust_Screenshot_Evidence.pdf) and [live simulation demonstration](../portfolio/Autenia_Murray_Zero_Trust_Live_Demo.mp4).

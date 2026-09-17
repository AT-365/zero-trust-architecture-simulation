# Architecture and policy flow

## Components

| Component | Implementation | Responsibility |
|---|---|---|
| Policy information | `User`, `Device`, and `Resource` records | Supplies identity, authorization, device-posture, sensitivity, and segment attributes |
| Policy decision point | `ZeroTrustPolicyEngine.evaluate()` | Applies every relevant control and produces an allow/deny decision with reasons |
| Policy enforcement simulation | `AccessRequest` scenarios | Represents the request context presented to the decision point |
| Monitoring | `MonitoringEngine.inspect()` | Creates a denial alert and escalates repeated failures |
| Evidence | CSV writers in `main()` | Preserves decisions, alerts, and expected-versus-actual test results |

## Decision sequence

Each request is denied if any applicable control fails:

1. The user must exist and be active.
2. The device must exist and belong to the requesting user.
3. The resource must exist.
4. The user's role must be permitted for the resource.
5. MFA must be enabled when the resource requires it.
6. A managed device must be used when required.
7. The device must be compliant.
8. High- or critical-sensitivity resources require device encryption.
9. Devices with a risk score of 70 or higher are denied.
10. The source network segment must be approved for the destination resource.

An empty reason list produces `ALLOW`; one or more failed controls produce `DENY`. The decision is compared with the scenario's expected outcome, producing a reproducible pass/fail record.

## Modeled segments and resources

| Resource | Sensitivity | Approved source segments |
|---|---|---|
| HR records | High | HR, IT Admin |
| Finance database | Critical | Finance, IT Admin |
| Administration console | Critical | IT Admin |
| Public portal | Low | Guest, HR, Finance, IT Admin |

The source code uses synthetic names and identifiers; no organizational production data is included.


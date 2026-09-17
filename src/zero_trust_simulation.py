from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import csv


@dataclass
class User:
    user_id: str
    name: str
    role: str
    active: bool
    mfa_enabled: bool


@dataclass
class Device:
    device_id: str
    owner_id: str
    managed: bool
    compliant: bool
    encrypted: bool
    risk_score: int


@dataclass
class Resource:
    resource_id: str
    name: str
    segment: str
    sensitivity: str
    allowed_roles: list
    requires_managed_device: bool
    requires_mfa: bool


@dataclass
class AccessRequest:
    request_id: str
    user_id: str
    device_id: str
    source_segment: str
    resource_id: str
    scenario: str
    expected_decision: str


class ZeroTrustPolicyEngine:
    def __init__(self, users, devices, resources):
        self.users = users
        self.devices = devices
        self.resources = resources
        self.allowed_segment_paths = {
            "HR_RECORDS": ["HR", "IT_ADMIN"],
            "FINANCE_DB": ["FINANCE", "IT_ADMIN"],
            "ADMIN_CONSOLE": ["IT_ADMIN"],
            "PUBLIC_PORTAL": ["GUEST", "HR", "FINANCE", "IT_ADMIN"],
        }

    def evaluate(self, request):
        timestamp = datetime.now(timezone.utc).isoformat()
        reasons = []

        user = self.users.get(request.user_id)
        device = self.devices.get(request.device_id)
        resource = self.resources.get(request.resource_id)

        if user is None:
            reasons.append("Unknown user")
        elif not user.active:
            reasons.append("Inactive user account")

        if device is None:
            reasons.append("Unknown device")
        elif user and device.owner_id != user.user_id:
            reasons.append("Device is not assigned to requesting user")

        if resource is None:
            reasons.append("Unknown resource")

        if user and resource:
            if user.role not in resource.allowed_roles:
                reasons.append("User role is not authorized for this resource")
            if resource.requires_mfa and not user.mfa_enabled:
                reasons.append("MFA is required but not enabled")

        if device and resource:
            if resource.requires_managed_device and not device.managed:
                reasons.append("Managed device is required")
            if not device.compliant:
                reasons.append("Device is not compliant")
            if resource.sensitivity in ["High", "Critical"] and not device.encrypted:
                reasons.append("Encrypted device is required for sensitive resource")
            if device.risk_score >= 70:
                reasons.append("Device risk score is too high")

        if resource:
            allowed_sources = self.allowed_segment_paths.get(resource.resource_id, [])
            if request.source_segment not in allowed_sources:
                reasons.append("Source segment is blocked by micro-segmentation policy")

        decision = "ALLOW" if not reasons else "DENY"

        return {
            "timestamp": timestamp,
            "request_id": request.request_id,
            "scenario": request.scenario,
            "user_id": request.user_id,
            "device_id": request.device_id,
            "source_segment": request.source_segment,
            "resource_id": request.resource_id,
            "decision": decision,
            "expected_decision": request.expected_decision,
            "policy_result": "PASS" if decision == request.expected_decision else "FAIL",
            "reason": "; ".join(reasons) if reasons else "Access approved by Zero Trust policy"
        }


class MonitoringEngine:
    def __init__(self):
        self.denied_by_device = {}

    def inspect(self, record):
        alerts = []

        if record["decision"] == "DENY":
            device_id = record["device_id"]
            self.denied_by_device[device_id] = self.denied_by_device.get(device_id, 0) + 1

            alerts.append({
                "timestamp": record["timestamp"],
                "request_id": record["request_id"],
                "severity": "MEDIUM",
                "alert_type": "POLICY_DENIAL",
                "message": f"Access denied for {record['user_id']} to {record['resource_id']}: {record['reason']}"
            })

            if self.denied_by_device[device_id] >= 3:
                alerts.append({
                    "timestamp": record["timestamp"],
                    "request_id": record["request_id"],
                    "severity": "HIGH",
                    "alert_type": "REPEATED_DENIALS",
                    "message": f"Device {device_id} triggered repeated denied access attempts"
                })

        return alerts


def build_lab_data():
    users = {
        "u_hr": User("u_hr", "HR Analyst", "HR", True, True),
        "u_fin": User("u_fin", "Finance Analyst", "FINANCE", True, True),
        "u_admin": User("u_admin", "Systems Admin", "ADMIN", True, True),
        "u_guest": User("u_guest", "Guest User", "GUEST", True, False),
        "u_disabled": User("u_disabled", "Former Employee", "HR", False, True),
    }

    devices = {
        "d_hr_laptop": Device("d_hr_laptop", "u_hr", True, True, True, 20),
        "d_fin_bad": Device("d_fin_bad", "u_fin", True, False, True, 55),
        "d_admin": Device("d_admin", "u_admin", True, True, True, 15),
        "d_guest": Device("d_guest", "u_guest", False, True, False, 30),
        "d_unknown": Device("d_unknown", "u_guest", False, False, False, 85),
    }

    resources = {
        "HR_RECORDS": Resource("HR_RECORDS", "Human Resources Records", "HR", "High", ["HR", "ADMIN"], True, True),
        "FINANCE_DB": Resource("FINANCE_DB", "Finance Database", "FINANCE", "Critical", ["FINANCE", "ADMIN"], True, True),
        "ADMIN_CONSOLE": Resource("ADMIN_CONSOLE", "Server Administration Console", "IT_ADMIN", "Critical", ["ADMIN"], True, True),
        "PUBLIC_PORTAL": Resource("PUBLIC_PORTAL", "Public Information Portal", "PUBLIC", "Low", ["GUEST", "HR", "FINANCE", "ADMIN"], False, False),
    }

    return users, devices, resources


def build_test_requests():
    return [
        AccessRequest("T01", "u_hr", "d_hr_laptop", "HR", "HR_RECORDS", "HR user accesses HR records from compliant device", "ALLOW"),
        AccessRequest("T02", "u_hr", "d_hr_laptop", "HR", "FINANCE_DB", "HR user attempts Finance database access", "DENY"),
        AccessRequest("T03", "u_fin", "d_fin_bad", "FINANCE", "FINANCE_DB", "Finance user uses noncompliant device", "DENY"),
        AccessRequest("T04", "u_admin", "d_admin", "IT_ADMIN", "ADMIN_CONSOLE", "Admin accesses admin console from trusted segment", "ALLOW"),
        AccessRequest("T05", "u_guest", "d_guest", "GUEST", "HR_RECORDS", "Guest attempts internal HR access", "DENY"),
        AccessRequest("T06", "u_guest", "d_unknown", "GUEST", "ADMIN_CONSOLE", "High-risk unmanaged device attempts admin access", "DENY"),
        AccessRequest("T07", "u_hr", "d_hr_laptop", "GUEST", "HR_RECORDS", "Valid HR user attempts access from wrong segment", "DENY"),
        AccessRequest("T08A", "u_guest", "d_unknown", "GUEST", "FINANCE_DB", "Repeated failed attempt 1", "DENY"),
        AccessRequest("T08B", "u_guest", "d_unknown", "GUEST", "FINANCE_DB", "Repeated failed attempt 2", "DENY"),
        AccessRequest("T08C", "u_guest", "d_unknown", "GUEST", "FINANCE_DB", "Repeated failed attempt 3", "DENY"),
        AccessRequest("T09", "u_fin", "d_fin_bad", "FINANCE", "FINANCE_DB", "Device remains noncompliant after prior denial", "DENY"),
        AccessRequest("T10", "u_guest", "d_guest", "GUEST", "PUBLIC_PORTAL", "Guest accesses public portal", "ALLOW"),
        AccessRequest("T11", "u_disabled", "d_hr_laptop", "HR", "HR_RECORDS", "Inactive account attempts access", "DENY"),
    ]


def write_csv(path, rows, fieldnames):
    with open(path, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    base_dir = Path(__file__).resolve().parents[1]
    results_dir = base_dir / "results"
    results_dir.mkdir(exist_ok=True)

    users, devices, resources = build_lab_data()
    requests = build_test_requests()

    policy_engine = ZeroTrustPolicyEngine(users, devices, resources)
    monitor = MonitoringEngine()

    access_log = []
    alerts = []

    for request in requests:
        record = policy_engine.evaluate(request)
        access_log.append(record)
        alerts.extend(monitor.inspect(record))

    summary = [
        {
            "request_id": row["request_id"],
            "scenario": row["scenario"],
            "expected_decision": row["expected_decision"],
            "actual_decision": row["decision"],
            "policy_result": row["policy_result"]
        }
        for row in access_log
    ]

    write_csv(
        results_dir / "access_log.csv",
        access_log,
        ["timestamp", "request_id", "scenario", "user_id", "device_id", "source_segment",
         "resource_id", "decision", "expected_decision", "policy_result", "reason"]
    )

    write_csv(
        results_dir / "alerts.csv",
        alerts,
        ["timestamp", "request_id", "severity", "alert_type", "message"]
    )

    write_csv(
        results_dir / "test_summary.csv",
        summary,
        ["request_id", "scenario", "expected_decision", "actual_decision", "policy_result"]
    )

    total = len(access_log)
    passed = sum(1 for row in access_log if row["policy_result"] == "PASS")
    allowed = sum(1 for row in access_log if row["decision"] == "ALLOW")
    denied = sum(1 for row in access_log if row["decision"] == "DENY")

    print("Zero Trust simulation complete")
    print(f"Total access requests: {total}")
    print(f"Allowed requests: {allowed}")
    print(f"Denied requests: {denied}")
    print(f"Policy tests passed: {passed}/{total}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Results saved in: {results_dir}")


if __name__ == "__main__":
    main()

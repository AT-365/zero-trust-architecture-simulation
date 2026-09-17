import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "zero_trust_simulation.py"
SPEC = importlib.util.spec_from_file_location("zero_trust_simulation", MODULE_PATH)
zt = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(zt)


class ZeroTrustSimulationTests(unittest.TestCase):
    def setUp(self):
        users, devices, resources = zt.build_lab_data()
        self.requests = zt.build_test_requests()
        self.policy = zt.ZeroTrustPolicyEngine(users, devices, resources)
        self.monitor = zt.MonitoringEngine()

    def evaluate_all(self):
        records = []
        alerts = []
        for request in self.requests:
            record = self.policy.evaluate(request)
            records.append(record)
            alerts.extend(self.monitor.inspect(record))
        return records, alerts

    def test_all_defined_policy_scenarios_pass(self):
        records, _ = self.evaluate_all()
        self.assertEqual(13, len(records))
        self.assertTrue(all(row["policy_result"] == "PASS" for row in records))

    def test_expected_decision_distribution(self):
        records, _ = self.evaluate_all()
        self.assertEqual(3, sum(row["decision"] == "ALLOW" for row in records))
        self.assertEqual(10, sum(row["decision"] == "DENY" for row in records))

    def test_monitoring_generates_expected_alerts(self):
        _, alerts = self.evaluate_all()
        self.assertEqual(13, len(alerts))
        self.assertEqual(10, sum(a["alert_type"] == "POLICY_DENIAL" for a in alerts))
        self.assertEqual(3, sum(a["alert_type"] == "REPEATED_DENIALS" for a in alerts))

    def test_unknown_user_is_denied(self):
        request = zt.AccessRequest(
            "EDGE01", "missing", "d_guest", "GUEST", "PUBLIC_PORTAL",
            "Unknown identity attempts public access", "DENY"
        )
        record = self.policy.evaluate(request)
        self.assertEqual("DENY", record["decision"])
        self.assertIn("Unknown user", record["reason"])


if __name__ == "__main__":
    unittest.main()


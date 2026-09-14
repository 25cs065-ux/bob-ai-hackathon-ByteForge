"""
Smoke test for Module 1 — Ingestion & Correlation.
Run from the src/ directory:  python smoke_test.py
"""
import sys
sys.path.insert(0, ".")

from shared.schemas import NormalizedAlert
from ingestion.ingestion_pipeline import run_ingestion
from ingestion.multi_source_ingestion import collect_raw_alerts
from ingestion.normalization import normalize_alerts
from ingestion.alert_correlation import correlate_alerts
from ingestion.incident_clustering import build_incidents

PASS = "PASSED"
FAIL = "FAILED"


def sep(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


# ---------------------------------------------------------------------------
# TEST 1 — All sources
# ---------------------------------------------------------------------------
sep("TEST 1 - All sources")
incidents = run_ingestion(["siem", "sensor", "intel", "satellite"])
print(f"Incidents produced: {len(incidents)}")
for inc in incidents:
    print(f"  Incident {inc.incident_id[:8]}... - {len(inc.alerts)} alerts")
    for a in inc.alerts:
        print(
            f"    [{a.source:9s}] {a.alert_id:10s}  ts={a.timestamp}"
            f"  ip={a.ip}  asset={a.asset}  sev={a.severity}  type={a.event_type}"
        )
assert len(incidents) > 0, "Should have at least one incident"
print(PASS)


# ---------------------------------------------------------------------------
# TEST 2 — Empty source list
# ---------------------------------------------------------------------------
sep("TEST 2 - Empty source list")
empty = run_ingestion([])
assert empty == [], f"Expected [], got {empty}"
print(f"Result: {empty}")
print(PASS)


# ---------------------------------------------------------------------------
# TEST 3 — Every normalized alert has all required fields + non-empty raw_data
# ---------------------------------------------------------------------------
sep("TEST 3 - Normalization field check")
raw = collect_raw_alerts(["siem", "sensor", "intel", "satellite"])
normed = normalize_alerts(raw)
required = ["alert_id", "timestamp", "source", "ip", "asset", "severity",
            "event_type", "raw_data"]
for a in normed:
    for f in required:
        assert hasattr(a, f), f"Missing field {f} on {a.alert_id}"
    assert isinstance(a.raw_data, dict), f"raw_data not dict on {a.alert_id}"
    assert a.raw_data, f"raw_data empty for {a.alert_id}"
print(f"All {len(normed)} alerts have all required fields with non-empty raw_data")
print(PASS)


# ---------------------------------------------------------------------------
# TEST 4 — Explicit correlation + separation
# ---------------------------------------------------------------------------
sep("TEST 4 - Correlation separation")
a = NormalizedAlert("A", "2024-01-15T10:00:00Z", "test",
                    ip="1.2.3.4", asset="srv", severity="high",
                    event_type="login_failure")
b = NormalizedAlert("B", "2024-01-15T10:05:00Z", "test",
                    ip="1.2.3.4", asset="srv", severity="high",
                    event_type="powershell_execution")
c = NormalizedAlert("C", "2024-01-15T10:06:00Z", "test",
                    ip="9.9.9.9", asset="other", severity="low",
                    event_type="routine_health_check")
groups = correlate_alerts([a, b, c])
print(f"Groups: {len(groups)}")
for i, g in enumerate(groups):
    print(f"  Group {i + 1}: {[x.alert_id for x in g]}")
assert len(groups) == 2, f"Expected 2 groups, got {len(groups)}"
grp_ids = [set(x.alert_id for x in g) for g in groups]
assert {"A", "B"} in grp_ids, "A and B should be together"
assert {"C"} in grp_ids, "C should be alone"
print(PASS)


# ---------------------------------------------------------------------------
# TEST 5 — Multi-stage attack -> one incident
# ---------------------------------------------------------------------------
sep("TEST 5 - Multi-stage attack -> one incident")
stages = [
    NormalizedAlert("S1", "2024-01-15T10:00:00Z", "siem",
                    ip="203.0.113.10", asset="server-01",
                    severity="high", event_type="login_failure"),
    NormalizedAlert("S2", "2024-01-15T10:03:00Z", "siem",
                    ip="203.0.113.10", asset="server-01",
                    severity="critical", event_type="powershell_execution"),
    NormalizedAlert("S3", "2024-01-15T10:06:00Z", "siem",
                    ip="203.0.113.10", asset="server-01",
                    severity="critical", event_type="privilege_escalation"),
    NormalizedAlert("S4", "2024-01-15T10:09:00Z", "sensor",
                    ip="203.0.113.10", asset="server-01",
                    severity="critical", event_type="data_transfer"),
]
g5 = correlate_alerts(stages)
print(f"Groups: {len(g5)}")
assert len(g5) == 1, f"Expected 1 group, got {len(g5)}"
incs5 = build_incidents(g5)
assert len(incs5) == 1
inc5 = incs5[0]
print(f"Incident ID: {inc5.incident_id}")
print(f"Alerts in incident: {len(inc5.alerts)}")
assert len(inc5.alerts) == 4
print(PASS)


# ---------------------------------------------------------------------------
# TEST 6 — Non-IP indicator stays out of ip field
# ---------------------------------------------------------------------------
sep("TEST 6 - Intel non-IP indicator not in ip field")
intel_raw = [{
    "_source": "intel", "id": "INTEL-002",
    "time": "2024-01-15T10:02:00Z",
    "indicator": "malware-hash-abc123",
    "target": "server-01", "risk": "critical", "activity": "malware drop",
}]
normed_intel = normalize_alerts(intel_raw)
assert normed_intel[0].ip is None, f"ip should be None, got {normed_intel[0].ip}"
assert normed_intel[0].raw_data.get("indicator") == "malware-hash-abc123"
print(f"ip field = {normed_intel[0].ip!r}  (correct: None)")
print(f"raw_data['indicator'] = {normed_intel[0].raw_data['indicator']!r}")
print(PASS)


# ---------------------------------------------------------------------------
# TEST 7 — Unsupported source names are silently ignored
# ---------------------------------------------------------------------------
sep("TEST 7 - Unknown source silently ignored")
r = collect_raw_alerts(["unknown_source", "siem"])
assert all(a["_source"] == "siem" for a in r), "Only siem alerts expected"
print(f"Alerts from 'unknown_source' + 'siem': {len(r)} (all from siem)")
print(PASS)


# ---------------------------------------------------------------------------
# TEST 8 — Alias names resolve correctly
# ---------------------------------------------------------------------------
sep("TEST 8 - Source alias resolution")
r_alias   = collect_raw_alerts(["siem_feed"])
r_canonical = collect_raw_alerts(["siem"])
assert r_alias == r_canonical, "siem_feed and siem should return identical data"
print("siem_feed == siem: OK")
print(PASS)


# ---------------------------------------------------------------------------
# TEST 9 — Severity normalisation
# ---------------------------------------------------------------------------
sep("TEST 9 - Severity normalisation")
raw_sev = [
    {"_source": "siem", "event_time": "2024-01-01T00:00:00Z",
     "src_ip": "1.1.1.1", "hostname": "h", "level": "info", "event": "x"},
    {"_source": "siem", "event_time": "2024-01-01T00:00:00Z",
     "src_ip": "1.1.1.1", "hostname": "h", "level": "warning", "event": "x"},
    {"_source": "siem", "event_time": "2024-01-01T00:00:00Z",
     "src_ip": "1.1.1.1", "hostname": "h", "level": "critical", "event": "x"},
    {"_source": "siem", "event_time": "2024-01-01T00:00:00Z",
     "src_ip": "1.1.1.1", "hostname": "h", "level": "unknown_level", "event": "x"},
]
normed_sev = normalize_alerts(raw_sev)
expected = ["low", "medium", "critical", "low"]
for i, (n, e) in enumerate(zip(normed_sev, expected)):
    assert n.severity == e, f"Alert {i}: expected {e}, got {n.severity}"
    print(f"  {raw_sev[i]['level']:15s} -> {n.severity}")
print(PASS)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
print("ALL SMOKE TESTS PASSED")
print("=" * 70)

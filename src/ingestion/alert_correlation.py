from shared.schemas import NormalizedAlert
from typing import List
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Correlation configuration
# ---------------------------------------------------------------------------
_TIME_WINDOW_SECONDS = 15 * 60   # 15-minute sliding window

# Event types that represent meaningful attack-chain steps.
# Two alerts sharing a suspicious event type raise correlation confidence.
_SUSPICIOUS_EVENT_TYPES = {
    "login_failure",
    "powershell_execution",
    "privilege_escalation",
    "data_transfer",
    "lateral_movement",
    "malware_execution",
    "anomaly_detected",
    "physical_movement",
    "brute_force",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_ts(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp into a timezone-aware datetime.
    Returns datetime.min (UTC) on any parse failure so that time-distance
    checks degrade gracefully rather than raising exceptions.
    """
    if not ts:
        return datetime.min.replace(tzinfo=timezone.utc)
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return datetime.min.replace(tzinfo=timezone.utc)


def _within_window(dt_a: datetime, dt_b: datetime) -> bool:
    return abs((dt_a - dt_b).total_seconds()) <= _TIME_WINDOW_SECONDS


def _correlation_score(a: NormalizedAlert, b: NormalizedAlert,
                        dt_a: datetime, dt_b: datetime) -> int:
    """Return an integer score (0-4) representing how closely two alerts are
    correlated.  A score >= 2 is treated as a match.

    Scoring:
        +2  same IP  (strong signal)
        +2  same asset  (strong signal)
        +1  both have suspicious event types  (attack-chain signal)
        Time window is a hard gate — if they are too far apart the score
        is zeroed regardless.
    """
    if not _within_window(dt_a, dt_b):
        return 0

    score = 0

    # IP match — both must be non-empty
    if a.ip and b.ip and a.ip == b.ip:
        score += 2

    # Asset match — both must be non-empty
    if a.asset and b.asset and a.asset == b.asset:
        score += 2

    # Both are suspicious event types (attack-chain progression)
    if (a.event_type in _SUSPICIOUS_EVENT_TYPES and
            b.event_type in _SUSPICIOUS_EVENT_TYPES):
        score += 1

    return score


# ---------------------------------------------------------------------------
# Core grouping logic — union-find (path-compressed)
# ---------------------------------------------------------------------------

def _find(parent: List[int], i: int) -> int:
    while parent[i] != i:
        parent[i] = parent[parent[i]]   # path compression
        i = parent[i]
    return i


def _union(parent: List[int], rank: List[int], i: int, j: int) -> None:
    ri, rj = _find(parent, i), _find(parent, j)
    if ri == rj:
        return
    if rank[ri] < rank[rj]:
        ri, rj = rj, ri
    parent[rj] = ri
    if rank[ri] == rank[rj]:
        rank[ri] += 1


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def correlate_alerts(alerts: List[NormalizedAlert]) -> List[List[NormalizedAlert]]:
    """
    Feature #3: AI Alert Correlation.
    Group alerts that are likely part of the same attack.
    Return a list of groups (each group = list of related alerts).

    Strategy (deterministic, no external AI):
    - Sort alerts by timestamp for stable ordering.
    - Score every pair of alerts using IP, asset, and event-type signals
      gated by a 15-minute time window.
    - Merge pairs with score >= 2 using a union-find structure.
    - Every alert belongs to exactly one group; no alert is silently dropped.
    """
    if not alerts:
        return []

    # Stable sort by timestamp so processing order is deterministic
    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
    n = len(sorted_alerts)

    # Pre-parse timestamps once
    datetimes = [_parse_ts(a.timestamp) for a in sorted_alerts]

    # Initialise union-find
    parent = list(range(n))
    rank   = [0] * n

    # Pairwise correlation — O(n²) is fine for prototype-scale data
    for i in range(n):
        for j in range(i + 1, n):
            score = _correlation_score(
                sorted_alerts[i], sorted_alerts[j],
                datetimes[i], datetimes[j],
            )
            if score >= 2:
                _union(parent, rank, i, j)

    # Collect groups, preserving intra-group timestamp order
    group_map: dict = {}
    for i in range(n):
        root = _find(parent, i)
        group_map.setdefault(root, []).append(sorted_alerts[i])

    # Return groups sorted by the earliest alert timestamp in each group
    groups = list(group_map.values())
    groups.sort(key=lambda g: g[0].timestamp)

    return groups

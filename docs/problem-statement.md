# Problem Statement

## Background

Modern defence and security operations rely on a growing web of monitoring
systems — SIEM platforms, network and endpoint cyber sensors, human-generated
intelligence reports, and increasingly, satellite and geospatial feeds that
correlate physical activity with cyber events. Each of these systems was
built independently, uses its own data format, and generates alerts on its
own timeline. A single moderately active network can produce thousands of
alerts per day across these sources, and defence analysts are expected to
review, correlate, and act on them fast enough to prevent real damage.

## The Problem

Defence analysts receive thousands of alerts daily from SIEM systems,
cyber sensors, intelligence reports, and satellite feeds, each in a
different format, with no automatic way to tell which alerts belong to
the same underlying attack. Analysts must manually cross-reference alerts
by hand to determine whether five separate low-severity notices are
actually one coordinated intrusion, or whether a single critical alert is
an isolated false alarm. This manual correlation process does not scale:
no human team can read every alert in real time, meaning genuine threats
can be missed simply due to alert volume, while significant analyst hours
are spent chasing alerts that turn out to be false positives.

## Who is Affected

Defence and security operations center (SOC) analysts responsible for
triaging multi-source alert feeds in real time, and the commanders and
decision-makers above them who depend on analysts to surface only the
threats that genuinely require action. This includes analysts working
across disconnected tools — a SIEM console, a separate sensor dashboard,
an intelligence report inbox, and (in defence-specific contexts) satellite
or geospatial monitoring feeds — who currently have no single place to see
a unified, correlated view of an unfolding incident.

## Why It Matters

Missing a genuine threat in this environment is catastrophic — a
correlated, multi-stage attack that goes unrecognized because its alerts
were never linked together can escalate from initial access to data
exfiltration or system compromise before anyone notices the pattern.
Conversely, every hour analysts spend manually chasing false positives is
an hour not spent on real threats, and with alert volumes in the
thousands-per-day range, this manual overhead is a direct and continuous
drain on already-limited analyst capacity. Commanders also need threat
assessments delivered in a clear, structured format — traditionally BLUF
(Bottom Line Up Front) — within minutes, not hours, so that operational
decisions can be made before a situation escalates further.

## Why Existing Solutions Fall Short

Most existing SIEM and sensor platforms are source-specific: they surface
alerts well within their own tool but do not natively correlate an alert
from a firewall with a related alert from an intelligence report or a
satellite feed. Analysts are left to bridge these gaps manually, cross-
referencing timestamps, IP addresses, and affected assets by hand across
multiple disconnected dashboards. Even where basic alert aggregation
exists, it typically stops at listing alerts together rather than
determining whether they represent a genuine coordinated threat, mapping
the behaviour to a recognized attacker technique framework (such as MITRE
ATT&CK), or producing a decision-ready summary for a commander. This gap —
between raw multi-source alert volume and a prioritized, explained,
commander-ready threat picture — is what this project addresses directly.

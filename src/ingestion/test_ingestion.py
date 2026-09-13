from ingestion.ingestion_pipeline import run_ingestion

# Pass source NAMES — collect_raw_alerts() already has realistic
# simulated alert data built in for each of these sources.
sample_sources = ["siem", "sensor", "intel", "satellite"]

incidents = run_ingestion(sample_sources)

print(f"Total incidents created: {len(incidents)}")
for inc in incidents:
    print(f"\nIncident ID: {inc.incident_id}")
    print(f"Number of alerts grouped: {len(inc.alerts)}")
    for alert in inc.alerts:
        print(f"  - {alert.source} | {alert.event_type} | {alert.severity} | asset={alert.asset}")
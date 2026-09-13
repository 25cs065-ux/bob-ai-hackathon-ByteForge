from shared.schemas import Incident

# ---------------------------------------------------------------------------
# raw_data keys that may carry physical / geospatial information.
# ---------------------------------------------------------------------------
_LOCATION_FIELDS  = ("asset_location", "location")
_COORD_FIELDS     = ("latitude", "longitude", "geo")
_SIGNAL_FLAGS     = ("satellite_flag", "physical_signal")
_MOVEMENT_FIELDS  = ("movement_detected",)
_DISTANCE_FIELDS  = ("distance",)

_NO_SIGNAL = {"status": "no_physical_signal", "correlated": False}


def _is_meaningful(value) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip() != ""
    if isinstance(value, (dict, list)):
        return len(value) > 0
    return True


def _pick_meaningful(raw_data: dict, keys) -> tuple:
    for k in keys:
        if k in raw_data and _is_meaningful(raw_data[k]):
            return k, raw_data[k]
    return None, None


def _has_physical_signal(raw_data: dict) -> bool:
    all_keys = (
        _LOCATION_FIELDS
        + _COORD_FIELDS
        + _SIGNAL_FLAGS
        + _MOVEMENT_FIELDS
        + _DISTANCE_FIELDS
    )
    return any(
        k in raw_data and _is_meaningful(raw_data[k])
        for k in all_keys
    )


def _fuse_alert(alert) -> dict:
    raw    = alert.raw_data if isinstance(alert.raw_data, dict) else {}
    result = {}

    if alert.asset:
        result["asset"] = alert.asset

    loc_key, loc_val = _pick_meaningful(raw, _LOCATION_FIELDS)
    if loc_val is not None:
        result["asset_location"] = loc_val

    for k in _COORD_FIELDS:
        if k in raw and _is_meaningful(raw[k]):
            result[k] = raw[k]

    sat_key, sat_val = _pick_meaningful(raw, _SIGNAL_FLAGS)
    if sat_key is not None:
        result["satellite_flag"] = bool(sat_val)

    phys_label = None
    if "physical_signal" in raw and _is_meaningful(raw["physical_signal"]):
        v = raw["physical_signal"]
        phys_label = str(v) if not isinstance(v, bool) else "physical_signal"
    else:
        mov_key, _ = _pick_meaningful(raw, _MOVEMENT_FIELDS)
        if mov_key:
            phys_label = mov_key
        else:
            dist_key, dist_val = _pick_meaningful(raw, _DISTANCE_FIELDS)
            if dist_key is not None:
                phys_label = f"{dist_key}:{dist_val}"

    if phys_label:
        result["physical_signal"] = phys_label

    asset_label = alert.asset or "the asset"
    signal_desc = phys_label or "a geospatial signal"
    result["correlation"] = (
        f"Cyber activity against {asset_label} coincides with "
        f"a simulated physical signal ({signal_desc})."
    )
    result["correlated"] = True

    return result


def fuse_cyber_physical(incident: Incident) -> Incident:
    """
    Feature #20: Cyber-Physical Threat Fusion (Innovation - Option A).
    """
    if not incident.alerts:
        incident.physical_correlation = dict(_NO_SIGNAL)
        return incident

    for alert in incident.alerts:
        try:
            raw = alert.raw_data if isinstance(alert.raw_data, dict) else {}
            if _has_physical_signal(raw):
                incident.physical_correlation = _fuse_alert(alert)
                return incident
        except Exception:
            continue

    incident.physical_correlation = dict(_NO_SIGNAL)
    return incident


if __name__ == "__main__":
    from shared.schemas import Incident, NormalizedAlert

    sample_alert = NormalizedAlert(
        alert_id="TEST-001",
        timestamp="2024-01-15T10:00:00Z",
        source="satellite",
        ip=None,
        asset="server-01",
        severity="high",
        event_type="physical_movement",
        raw_data={"asset_location": "datacenter-zone-A", "movement_detected": True, "satellite_flag": True},
    )
    incident = Incident(incident_id="INC-TEST-001", alerts=[sample_alert])

    result = fuse_cyber_physical(incident)
    print("physical_correlation:", result.physical_correlation)
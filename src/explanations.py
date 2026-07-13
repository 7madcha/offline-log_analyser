"""Human-readable, evidence-based incident explanations."""

from __future__ import annotations


def build_incident_explanation(incident: dict) -> str:
    """Generate an explanation using actual incident values."""
    src_ip = incident.get("src_ip", "unknown")
    alert_count = int(incident.get("alert_count", 0))
    alert_types = incident.get("alert_types", "")
    event_count = int(incident.get("event_count", 0))
    affected_destinations = incident.get("affected_destinations", "")
    affected_ports = incident.get("affected_ports", "")
    risk_score = int(incident.get("risk_score", 0))

    parts = [
        f"The source IP {src_ip} produced {alert_count} alert(s) involving {event_count} event(s).",
        f"Observed alert type(s): {alert_types}.",
    ]
    if affected_destinations:
        destination_count = len([value for value in str(affected_destinations).split(", ") if value])
        parts.append(f"The activity affected {destination_count} destination value(s).")
    if affected_ports:
        port_count = len([value for value in str(affected_ports).split(", ") if value])
        parts.append(f"The activity involved {port_count} destination port value(s).")
    parts.append(
        f"These suspicious behaviors produced a risk score of {risk_score} out of 100 and require investigation."
    )
    return " ".join(parts)

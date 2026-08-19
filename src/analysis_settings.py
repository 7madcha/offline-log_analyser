"""Validated, analysis-scoped settings for the isolated CUSTOM detector path."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class AnalysisMode(str, Enum):
    """The one effective threshold mode used for an analysis."""

    STANDARD = "STANDARD"
    BASELINE = "BASELINE"
    CUSTOM = "CUSTOM"


class SettingsValidationError(ValueError):
    """Raised when custom analysis settings are missing or invalid."""


_SETTING_FIELDS = (
    "brute_force_blocked_attempts",
    "brute_force_window_minutes",
    "brute_force_destination_ports",
    "port_scan_unique_ports",
    "port_scan_window_minutes",
    "host_scan_unique_destinations",
    "host_scan_window_minutes",
    "large_transfer_percentile",
    "large_transfer_minimum_bytes",
    "off_hours_start_hour",
    "off_hours_end_hour",
)


def _require_positive_int(name: str, value: Any) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SettingsValidationError(f"{name} must be an integer.")
    if value <= 0:
        raise SettingsValidationError(f"{name} must be greater than zero.")


def _require_hour(name: str, value: Any, *, allow_24: bool = False) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SettingsValidationError(f"{name} must be an integer hour.")
    maximum = 24 if allow_24 else 23
    if not 0 <= value <= maximum:
        raise SettingsValidationError(f"{name} must be between 0 and {maximum}.")


@dataclass(frozen=True, slots=True)
class AnalysisSettings:
    """Explicit thresholds used by one CUSTOM analysis run.

    There are deliberately no implicit defaults. Use :meth:`from_config` when
    the desired custom values should initially match the existing standard
    detector configuration.
    """

    brute_force_blocked_attempts: int
    brute_force_window_minutes: int
    brute_force_destination_ports: tuple[int, ...]
    port_scan_unique_ports: int
    port_scan_window_minutes: int
    host_scan_unique_destinations: int
    host_scan_window_minutes: int
    large_transfer_percentile: float
    large_transfer_minimum_bytes: int
    off_hours_start_hour: int
    off_hours_end_hour: int

    def __post_init__(self) -> None:
        for name in (
            "brute_force_blocked_attempts",
            "brute_force_window_minutes",
            "port_scan_unique_ports",
            "port_scan_window_minutes",
            "host_scan_unique_destinations",
            "host_scan_window_minutes",
            "large_transfer_minimum_bytes",
        ):
            _require_positive_int(name, getattr(self, name))

        ports = self.brute_force_destination_ports
        if not isinstance(ports, tuple) or not ports:
            raise SettingsValidationError("brute_force_destination_ports must be a non-empty tuple of ports.")
        for port in ports:
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise SettingsValidationError("Every brute_force_destination_ports value must be an integer from 1 to 65535.")
        if len(set(ports)) != len(ports):
            raise SettingsValidationError("brute_force_destination_ports must not contain duplicates.")

        percentile = self.large_transfer_percentile
        if isinstance(percentile, bool) or not isinstance(percentile, (int, float)):
            raise SettingsValidationError("large_transfer_percentile must be numeric.")
        if not 0 < float(percentile) <= 1:
            raise SettingsValidationError("large_transfer_percentile must be greater than 0 and at most 1.")

        _require_hour("off_hours_start_hour", self.off_hours_start_hour)
        _require_hour("off_hours_end_hour", self.off_hours_end_hour, allow_24=True)
        if self.off_hours_start_hour % 24 == self.off_hours_end_hour % 24:
            raise SettingsValidationError("The off-hours start and end must describe a non-zero time range.")

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "AnalysisSettings":
        """Build settings from a complete flat mapping with clear errors."""
        if not isinstance(values, Mapping):
            raise SettingsValidationError("Custom settings must be provided as a mapping.")
        if any(not isinstance(key, str) for key in values):
            raise SettingsValidationError("Custom setting names must be strings.")
        missing = sorted(set(_SETTING_FIELDS) - set(values))
        if missing:
            raise SettingsValidationError(f"Missing required custom setting(s): {', '.join(missing)}")
        unexpected = sorted(set(values) - set(_SETTING_FIELDS))
        if unexpected:
            raise SettingsValidationError(f"Unknown custom setting(s): {', '.join(unexpected)}")

        normalized = dict(values)
        ports = normalized["brute_force_destination_ports"]
        if isinstance(ports, list):
            normalized["brute_force_destination_ports"] = tuple(ports)
        try:
            return cls(**normalized)
        except TypeError as exc:
            raise SettingsValidationError(f"Invalid custom settings: {exc}") from exc

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> "AnalysisSettings":
        """Create explicit custom values equivalent to the standard config."""
        try:
            return cls(
                brute_force_blocked_attempts=config["brute_force"]["blocked_attempts"],
                brute_force_window_minutes=config["brute_force"]["window_minutes"],
                brute_force_destination_ports=tuple(config["brute_force"]["destination_ports"]),
                port_scan_unique_ports=config["port_scan"]["unique_ports"],
                port_scan_window_minutes=config["port_scan"]["window_minutes"],
                host_scan_unique_destinations=config["host_scan"]["unique_destinations"],
                host_scan_window_minutes=config["host_scan"]["window_minutes"],
                large_transfer_percentile=config["large_transfer"]["percentile"],
                large_transfer_minimum_bytes=config["large_transfer"]["minimum_bytes"],
                off_hours_start_hour=config["off_hours"]["start_hour"],
                off_hours_end_hour=config["off_hours"]["end_hour"],
            )
        except (KeyError, TypeError) as exc:
            raise SettingsValidationError(f"Existing config is missing a required detector setting: {exc}") from exc

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable audit record of the active thresholds."""
        return {
            "analysis_mode": AnalysisMode.CUSTOM.value,
            "brute_force": {
                "blocked_attempts": self.brute_force_blocked_attempts,
                "window_minutes": self.brute_force_window_minutes,
                "destination_ports": list(self.brute_force_destination_ports),
            },
            "port_scan": {
                "unique_ports": self.port_scan_unique_ports,
                "window_minutes": self.port_scan_window_minutes,
            },
            "host_scan": {
                "unique_destinations": self.host_scan_unique_destinations,
                "window_minutes": self.host_scan_window_minutes,
            },
            "large_transfer": {
                "percentile": float(self.large_transfer_percentile),
                "minimum_bytes": self.large_transfer_minimum_bytes,
            },
            "off_hours": {
                "start_hour": self.off_hours_start_hour,
                "end_hour": self.off_hours_end_hour,
            },
        }


def effective_analysis_mode(*, custom_settings_enabled: bool = False, baseline_enabled: bool = False) -> AnalysisMode:
    """Resolve unambiguous CUSTOM > BASELINE > STANDARD precedence."""
    if not isinstance(custom_settings_enabled, bool) or not isinstance(baseline_enabled, bool):
        raise TypeError("Analysis mode flags must be booleans.")
    if custom_settings_enabled:
        return AnalysisMode.CUSTOM
    if baseline_enabled:
        return AnalysisMode.BASELINE
    return AnalysisMode.STANDARD

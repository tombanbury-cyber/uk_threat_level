from __future__ import annotations

import asyncio
import logging
import re
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, MI5_URL, LEVEL_TO_NUMBER

_LOGGER = logging.getLogger(__name__)

# MI5 page contains a header line like:
# "Current Threat Level:  SUBSTANTIAL"
RE_THREAT = re.compile(r"Current\s+Threat\s+Level:\s*([A-Z]+)", re.IGNORECASE)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up via YAML (no options needed)."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up via config entry (optional)."""
    hass.data.setdefault(DOMAIN, {})
    coordinator = UKThreatLevelCoordinator(hass)
    await coordinator.async_config_entry_first_refresh()
    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, ["sensor"])
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, ["sensor"])
    if ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return ok


class UKThreatLevelCoordinator(DataUpdateCoordinator[dict]):
    def __init__(self, hass: HomeAssistant) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name="UK Threat Level",
            update_interval=timedelta(minutes=30),
        )

    async def _async_update_data(self) -> dict:
        session = async_get_clientsession(self.hass)
        try:
            resp = await session.get(MI5_URL, timeout=20)
            resp.raise_for_status()
            text = await resp.text()
        except Exception as err:
            raise UpdateFailed(f"Error fetching MI5 threat level: {err}") from err

        m = RE_THREAT.search(text)
        if not m:
            raise UpdateFailed("Could not parse threat level from MI5 page")

        level = m.group(1).upper()
        number = LEVEL_TO_NUMBER.get(level)

        if number is None:
            raise UpdateFailed(f"Unknown threat level parsed: {level}")

        return {
            "level": level,
            "number": number,
            "source": MI5_URL,
        }

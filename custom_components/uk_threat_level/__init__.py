import logging
import re
import xml.etree.ElementTree as ET
from datetime import timedelta

from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, MI5_RSS_URL, GOVUK_URL, LEVEL_TO_NUMBER

_LOGGER = logging.getLogger(__name__)

RE_LEVEL_WORD = re.compile(r"\b(LOW|MODERATE|SUBSTANTIAL|SEVERE|CRITICAL)\b", re.IGNORECASE)
RE_GOVUK = re.compile(r"threat to the UK .*? from terrorism is (\w+)", re.IGNORECASE)


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
        # 1) Try MI5 RSS feed first
        try:
            xml_text = await self._fetch_text(MI5_RSS_URL)
            level = self._parse_mi5_rss_level(xml_text)
            if level:
                return {
                    "level": level,
                    "number": LEVEL_TO_NUMBER[level],
                    "source": MI5_RSS_URL,
                }
            _LOGGER.warning("MI5 RSS fetched but could not parse level; falling back")
        except Exception as err:
            _LOGGER.warning("MI5 RSS fetch failed (%s); falling back", err)

        # 2) Fallback to GOV.UK (more tolerant of bots)
        try:
            html_text = await self._fetch_text(GOVUK_URL)
            level = self._parse_govuk_level(html_text)
            if not level:
                raise UpdateFailed("Fetched GOV.UK but could not parse level")
            return {
                "level": level,
                "number": LEVEL_TO_NUMBER[level],
                "source": GOVUK_URL,
            }
        except Exception as err:
            raise UpdateFailed(f"All sources failed: {err}") from err



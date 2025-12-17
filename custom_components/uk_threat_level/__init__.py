from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, MI5_RSS_URL, GOVUK_URL, LEVEL_TO_NUMBER

_LOGGER = logging.getLogger(__name__)

# Threat level words (we’ll search for these in MI5 RSS <title> text and GOV.UK HTML)
RE_LEVEL_WORD = re.compile(r"\b(LOW|MODERATE|SUBSTANTIAL|SEVERE|CRITICAL)\b", re.IGNORECASE)

# GOV.UK typically uses a phrase like: "... from terrorism is substantial."
RE_GOVUK_PHRASE = re.compile(r"from terrorism is\s+(low|moderate|substantial|severe|critical)\b", re.IGNORECASE)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up via YAML (we don't use YAML options, but HA expects this hook)."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up the integration from the UI (config flow)."""
    hass.data.setdefault(DOMAIN, {})
    coordinator = UKThreatLevelCoordinator(hass)
    await coordinator.async_config_entry_first_refresh()
    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, ["sensor"])
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload the integration."""
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

    async def _fetch_text(self, url: str) -> str:
        """Fetch text with headers that reduce 403/WAF blocking."""
        session = async_get_clientsession(self.hass)
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.9",
        }

        resp = await session.get(url, headers=headers, allow_redirects=True, timeout=20)

        if resp.status == 403:
            # Keep message short; body can be huge / binary / blocked page
            raise UpdateFailed(f"403 Forbidden from {url} (likely WAF/User-Agent filtering)")

        resp.raise_for_status()
        return await resp.text()

    def _normalize_level(self, text: str) -> str | None:
        m = RE_LEVEL_WORD.search(text or "")
        return m.group(1).upper() if m else None

    def _parse_mi5_rss_level(self, xml_text: str) -> str | None:
        """
        MI5 XML feed is RSS-like; we scan <title> elements for the level word.
        Example titles often include "Current threat level: SUBSTANTIAL"
        """
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return None

        for title_el in root.findall(".//title"):
            if title_el.text:
                lvl = self._normalize_level(title_el.text)
                if lvl:
                    return lvl
        return None

    def _parse_govuk_level(self, html_text: str) -> str | None:
        """
        GOV.UK page usually includes: "The threat to the UK ... from terrorism is substantial."
        """
        m = RE_GOVUK_PHRASE.search(html_text or "")
        if not m:
            return None
        return self._normalize_level(m.group(1))

    async def _async_update_data(self) -> dict:
        # 1) Try MI5 RSS/XML feed first
        try:
            xml_text = await self._fetch_text(MI5_RSS_URL)
            level = self._parse_mi5_rss_level(xml_text)
            if level and level in LEVEL_TO_NUMBER:
                return {"level": level, "number": LEVEL_TO_NUMBER[level], "source": MI5_RSS_URL}
            _LOGGER.warning("MI5 RSS fetched but could not parse a known level; falling back to GOV.UK")
        except Exception as err:
            _LOGGER.warning("MI5 RSS fetch/parse failed (%s); falling back to GOV.UK", err)

        # 2) Fallback to GOV.UK
        try:
            html_text = await self._fetch_text(GOVUK_URL)
            level = self._parse_govuk_level(html_text)
            if level and level in LEVEL_TO_NUMBER:
                return {"level": level, "number": LEVEL_TO_NUMBER[level], "source": GOVUK_URL}
            raise UpdateFailed("Fetched GOV.UK but could not parse a known level")
        except Exception as err:
            raise UpdateFailed(f"All sources failed: {err}") from err

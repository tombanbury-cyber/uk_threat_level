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


class UKThreatLevelCoordinator(DataUpdateCoordinator[dict]):
    def __init__(self, hass):
        super().__init__(
            hass,
            _LOGGER,
            name="UK Threat Level",
            update_interval=timedelta(minutes=30),
        )

    async def _fetch_text(self, url: str) -> str:
        session = async_get_clientsession(self.hass)
        headers = {
            # Helps avoid WAF blocks that trigger 403 for “script-y” clients
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.9",
        }
        resp = await session.get(url, headers=headers, allow_redirects=True, timeout=20)
        if resp.status == 403:
            raise UpdateFailed(f"403 Forbidden from {url} (likely WAF/User-Agent filtering)")
        resp.raise_for_status()
        return await resp.text()

    def _normalize_level(self, s: str) -> str | None:
        m = RE_LEVEL_WORD.search(s or "")
        if not m:
            return None
        return m.group(1).upper()

    def _parse_mi5_rss_level(self, xml_text: str) -> str | None:
        # Typical RSS: <channel><item><title>Current threat level: SUBSTANTIAL</title></item>...
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return None

        # Look for any <title> that contains a threat level word
        for title_el in root.findall(".//title"):
            if title_el.text:
                lvl = self._normalize_level(title_el.text)
                if lvl:
                    return lvl
        return None

    def _parse_govuk_level(self, html_text: str) -> str | None:
        # GOV.UK uses "… from terrorism is substantial."
        m = RE_GOVUK.search(html_text or "")
        if not m:
            return None
        return self._normalize_level(m.group(1))

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

from __future__ import annotations

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        [
            UKThreatLevelTextSensor(coordinator),
            UKThreatLevelNumberSensor(coordinator),
        ]
    )


class _Base(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, "mi5")},
            name="UK Threat Level (MI5)",
            manufacturer="MI5 (scraped)",
        )


class UKThreatLevelTextSensor(_Base):
    _attr_name = "Threat level"
    _attr_unique_id = f"{DOMAIN}_level"
    _attr_icon = "mdi:shield-alert-outline"

    @property
    def native_value(self):
        return self.coordinator.data.get("level")

    @property
    def extra_state_attributes(self):
        return {
            "source": self.coordinator.data.get("source"),
            "gauge_value": self.coordinator.data.get("number"),
        }


class UKThreatLevelNumberSensor(_Base):
    _attr_name = "Threat level (1-5)"
    _attr_unique_id = f"{DOMAIN}_number"
    _attr_native_unit_of_measurement = "level"
    _attr_icon = "mdi:gauge"

    @property
    def native_value(self):
        return self.coordinator.data.get("number")

    @property
    def extra_state_attributes(self):
        return {
            "label": self.coordinator.data.get("level"),
            "source": self.coordinator.data.get("source"),
        }

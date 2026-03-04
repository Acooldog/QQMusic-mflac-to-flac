import logging
from typing import Dict

from src.Application.format_policy_service import FormatPolicyService
from src.Infrastructure.local_config_repository import LocalConfigRepository


logger = logging.getLogger("qqmusic_decrypt.application.config")


class ConfigService:
    """Application service for settings load/merge/save."""

    def __init__(self, repository: LocalConfigRepository, policy: FormatPolicyService):
        self.repository = repository
        self.policy = policy

    def default_settings(self) -> Dict:
        return {
            "input": "",
            "output": "",
            "del": False,
            "wheel": False,
            "format_rules": dict(self.policy.DEFAULT_RULES),
            "format_whitelist": sorted(self.policy.FORMAT_WHITELIST),
        }

    def _extract_legacy_rule_overrides(self, raw: Dict) -> Dict[str, str]:
        return {
            "mflac": raw.get("format_mflac"),
            "mgg": raw.get("format_mgg"),
            "mmp4": raw.get("format_mmp4"),
        }

    def load(self) -> Dict:
        defaults = self.default_settings()
        raw = self.repository.load()

        merged = dict(defaults)
        for key in ("input", "output", "del", "wheel"):
            if key in raw:
                merged[key] = raw[key]

        normalized_rules = self.policy.normalize_rules(raw.get("format_rules", {}))
        legacy_overrides = self.policy.normalize_overrides(self._extract_legacy_rule_overrides(raw))
        if legacy_overrides:
            rules = dict(normalized_rules)
            rules.update(legacy_overrides)
            normalized_rules = self.policy.normalize_rules(rules)

        merged["format_rules"] = normalized_rules
        merged["format_whitelist"] = sorted(self.policy.FORMAT_WHITELIST)
        return merged

    def save(self, settings: Dict) -> None:
        defaults = self.default_settings()
        normalized = dict(defaults)

        for key in ("input", "output", "del", "wheel"):
            normalized[key] = settings.get(key, defaults[key])

        normalized["format_rules"] = self.policy.normalize_rules(settings.get("format_rules", {}))
        normalized["format_whitelist"] = sorted(self.policy.FORMAT_WHITELIST)

        self.repository.save(normalized)
        logger.info("Settings saved")

    def apply_cli_format_overrides(self, settings: Dict, overrides: Dict[str, str]) -> Dict:
        current = dict(settings.get("format_rules", {}))
        current.update(self.policy.normalize_overrides(overrides))
        settings["format_rules"] = self.policy.normalize_rules(current)
        return settings

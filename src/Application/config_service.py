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

    def load(self) -> Dict:
        defaults = self.default_settings()
        raw = self.repository.load()

        merged = dict(defaults)
        merged.update({k: v for k, v in raw.items() if k in defaults})

        merged["format_rules"] = self.policy.normalize_rules(raw.get("format_rules", {}))
        merged["format_whitelist"] = sorted(self.policy.FORMAT_WHITELIST)
        return merged

    def save(self, settings: Dict) -> None:
        # Normalize before persist to keep file clean and predictable.
        normalized = self.default_settings()
        normalized.update({k: settings.get(k, normalized[k]) for k in normalized if k not in ["format_rules", "format_whitelist"]})
        normalized["format_rules"] = self.policy.normalize_rules(settings.get("format_rules", {}))
        normalized["format_whitelist"] = sorted(self.policy.FORMAT_WHITELIST)
        self.repository.save(normalized)
        logger.info("配置已保存")

    def apply_cli_format_overrides(self, settings: Dict, overrides: Dict[str, str]) -> Dict:
        current = dict(settings.get("format_rules", {}))
        for src_ext, fmt in overrides.items():
            if fmt is None:
                continue
            current[src_ext] = fmt
        settings["format_rules"] = self.policy.normalize_rules(current)
        return settings


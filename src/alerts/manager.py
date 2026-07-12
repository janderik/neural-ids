from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import time
import uuid


@dataclass
class AlertRule:
    id: str
    name: str
    condition: str  # e.g., "attack_type == 'DoS'"
    action: str  # "notify", "block", "log"
    enabled: bool = True
    cooldown_seconds: int = 300
    last_triggered: float = 0


class AlertManager:
    def __init__(self):
        self._rules: List[AlertRule] = []
        self._alert_history: List[Dict[str, Any]] = []
        self._suppression_window: Dict[str, float] = {}

    def add_rule(self, name: str, condition: str, action: str = "notify", cooldown: int = 300) -> AlertRule:
        rule = AlertRule(
            id=str(uuid.uuid4())[:8],
            name=name,
            condition=condition,
            action=action,
            cooldown_seconds=cooldown,
        )
        self._rules.append(rule)
        return rule

    def process_alert(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        actions = []
        now = time.time()

        for rule in self._rules:
            if not rule.enabled:
                continue

            if self._evaluate_condition(rule.condition, alert):
                if now - rule.last_triggered < rule.cooldown_seconds:
                    continue

                rule.last_triggered = now
                actions.append({
                    "rule": rule.name,
                    "action": rule.action,
                    "alert_id": alert.get("id"),
                    "timestamp": now,
                })

        self._alert_history.append({
            "alert": alert,
            "actions": actions,
            "timestamp": now,
        })

        return actions

    def _evaluate_condition(self, condition: str, alert: Dict[str, Any]) -> bool:
        try:
            safe_vars = {
                "attack_type": alert.get("attack_type", ""),
                "severity": alert.get("severity", ""),
                "confidence": alert.get("confidence", 0),
                "src_ip": alert.get("src_ip", ""),
            }
            return bool(eval(condition, {"__builtins__": {}}, safe_vars))
        except Exception:
            return False

    def get_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._alert_history[-limit:]

    def get_rules(self) -> List[AlertRule]:
        return list(self._rules)

    def suppress_alert(self, attack_type: str, duration_seconds: int = 3600) -> None:
        self._suppression_window[attack_type] = time.time() + duration_seconds

    def is_suppressed(self, attack_type: str) -> bool:
        expires = self._suppression_window.get(attack_type, 0)
        if time.time() < expires:
            return True
        self._suppression_window.pop(attack_type, None)
        return False

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_rules": len(self._rules),
            "active_rules": sum(1 for r in self._rules if r.enabled),
            "total_alerts_processed": len(self._alert_history),
            "suppressed_types": list(self._suppression_window.keys()),
        }

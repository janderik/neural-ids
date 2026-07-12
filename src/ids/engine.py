from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


ATTACK_TYPES = ["Normal", "DoS", "Probe", "U2R", "R2L"]
SEVERITY_MAP = {
    "Normal": "info",
    "DoS": "critical",
    "Probe": "high",
    "U2R": "critical",
    "R2L": "high",
}


@dataclass
class ClassificationResult:
    attack_type: str
    confidence: float
    is_attack: bool
    model_scores: Dict[str, float] = field(default_factory=dict)
    severity: str = "info"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type,
            "confidence": self.confidence,
            "is_attack": self.is_attack,
            "model_scores": self.model_scores,
            "severity": self.severity,
            "timestamp": self.timestamp,
        }


@dataclass
class Alert:
    id: str
    attack_type: str
    severity: str
    src_ip: str
    dst_ip: str
    confidence: float
    details: str = ""
    timestamp: float = field(default_factory=time.time)
    acknowledged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "confidence": self.confidence,
            "details": self.details,
            "timestamp": self.timestamp,
            "acknowledged": self.acknowledged,
        }


class NeuralIDS:
    def __init__(self, model_dir: Optional[str] = None, confidence_threshold: float = 0.7):
        self.confidence_threshold = confidence_threshold
        self._lstm_model = None
        self._cnn_model = None
        self._ensemble_weights = {"lstm": 0.5, "cnn": 0.5}
        self._alerts: List[Alert] = []
        self._alert_counter = 0

        if model_dir:
            self.load_models(model_dir)

    def load_models(self, model_dir: str) -> None:
        import os
        import joblib

        lstm_path = os.path.join(model_dir, "lstm_v1.pkl")
        cnn_path = os.path.join(model_dir, "cnn_v1.pkl")

        if os.path.exists(lstm_path):
            self._lstm_model = joblib.load(lstm_path)
        if os.path.exists(cnn_path):
            self._cnn_model = joblib.load(cnn_path)

    def classify(self, features: Dict[str, float]) -> ClassificationResult:
        lstm_score = self._predict_lstm(features) if self._lstm_model else None
        cnn_score = self._predict_cnn(features) if self._cnn_model else None

        if lstm_score is not None and cnn_score is not None:
            combined = (
                self._ensemble_weights["lstm"] * lstm_score
                + self._ensemble_weights["cnn"] * cnn_score
            )
        elif lstm_score is not None:
            combined = lstm_score
        elif cnn_score is not None:
            combined = cnn_score
        else:
            combined = self._heuristic_classify(features)

        attack_type = self._score_to_class(combined)
        confidence = float(max(combined)) if hasattr(combined, "__len__") else float(combined)

        is_attack = attack_type != "Normal" and confidence >= self.confidence_threshold
        severity = SEVERITY_MAP.get(attack_type, "info")

        model_scores = {}
        if lstm_score is not None:
            model_scores["lstm"] = float(max(lstm_score)) if hasattr(lstm_score, "__len__") else float(lstm_score)
        if cnn_score is not None:
            model_scores["cnn"] = float(max(cnn_score)) if hasattr(cnn_score, "__len__") else float(cnn_score)

        return ClassificationResult(
            attack_type=attack_type,
            confidence=round(confidence, 4),
            is_attack=is_attack,
            model_scores=model_scores,
            severity=severity,
        )

    def _predict_lstm(self, features: Dict[str, float]):
        import numpy as np
        vector = np.array([[v for v in features.values()]])
        try:
            return self._lstm_model.predict_proba(vector)[0]
        except Exception:
            return None

    def _predict_cnn(self, features: Dict[str, float]):
        import numpy as np
        vector = np.array([[v for v in features.values()]])
        try:
            return self._cnn_model.predict_proba(vector)[0]
        except Exception:
            return None

    def _heuristic_classify(self, features: Dict[str, float]) -> list:
        scores = [0.95, 0.01, 0.01, 0.01, 0.02]

        packets = features.get("packets", 0)
        bytes_val = features.get("bytes", 0)
        duration = features.get("duration", 1)
        flags = features.get("flags_syn", 0)

        pps = packets / max(duration, 0.001)
        bps = bytes_val / max(duration, 0.001)

        if pps > 1000:
            scores = [0.02, 0.92, 0.03, 0.01, 0.02]
        elif pps > 500:
            scores = [0.10, 0.80, 0.05, 0.02, 0.03]
        elif flags > 0.8 and packets < 10:
            scores = [0.05, 0.02, 0.88, 0.02, 0.03]
        elif bytes_val > 100000 and duration < 1:
            scores = [0.03, 0.85, 0.05, 0.02, 0.05]

        return scores

    def _score_to_class(self, scores) -> str:
        if isinstance(scores, (int, float)):
            return "Normal" if scores < 0.5 else "DoS"
        import numpy as np
        idx = int(np.argmax(scores))
        return ATTACK_TYPES[idx] if idx < len(ATTACK_TYPES) else "Normal"

    def create_alert(self, result: ClassificationResult, src_ip: str, dst_ip: str) -> Optional[Alert]:
        if not result.is_attack:
            return None

        self._alert_counter += 1
        alert = Alert(
            id=f"IDS-{self._alert_counter:06d}",
            attack_type=result.attack_type,
            severity=result.severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            confidence=result.confidence,
            details=f"Neural IDS detected {result.attack_type} attack with {result.confidence:.1%} confidence",
        )
        self._alerts.append(alert)
        return alert

    def get_alerts(self, limit: int = 100, severity: Optional[str] = None) -> List[Alert]:
        alerts = self._alerts
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return alerts[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        total = len(self._alerts)
        by_type = {}
        by_severity = {}
        for a in self._alerts:
            by_type[a.attack_type] = by_type.get(a.attack_type, 0) + 1
            by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
        return {
            "total_alerts": total,
            "by_type": by_type,
            "by_severity": by_severity,
            "models_loaded": {
                "lstm": self._lstm_model is not None,
                "cnn": self._cnn_model is not None,
            },
        }

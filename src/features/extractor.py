import numpy as np
from typing import Dict, List, Optional


class FeatureExtractor:
    FEATURE_NAMES = [
        "packets",
        "bytes",
        "duration",
        "src_port",
        "dst_port",
        "protocol",
        "flags_syn",
        "flags_ack",
    ]

    def __init__(self):
        self._normalization_params: Optional[Dict[str, float]] = None

    def extract(self, flow: Dict) -> Dict[str, float]:
        features = {
            "packets": float(flow.get("packets", 0)),
            "bytes": float(flow.get("bytes", 0)),
            "duration": float(flow.get("duration", 0)),
            "src_port": float(flow.get("src_port", 0)),
            "dst_port": float(flow.get("dst_port", 0)),
            "protocol": float(flow.get("protocol", 0)),
        }

        flags = flow.get("flags", "")
        if isinstance(flags, str):
            features["flags_syn"] = 1.0 if "SYN" in flags.upper() else 0.0
            features["flags_ack"] = 1.0 if "ACK" in flags.upper() else 0.0
        else:
            features["flags_syn"] = float(flags)
            features["flags_ack"] = 0.0

        return features

    def extract_batch(self, flows: List[Dict]) -> List[Dict[str, float]]:
        return [self.extract(flow) for flow in flows]

    def to_numpy(self, features: Dict[str, float]) -> np.ndarray:
        return np.array([[features.get(f, 0.0) for f in self.FEATURE_NAMES]])

    def normalize(self, features: Dict[str, float]) -> Dict[str, float]:
        if self._normalization_params is None:
            return features

        normalized = {}
        for key, value in features.items():
            params = self._normalization_params.get(key)
            if params:
                mean, std = params
                normalized[key] = (value - mean) / max(std, 1e-8)
            else:
                normalized[key] = value
        return normalized

    def fit_normalization(self, feature_vectors: List[Dict[str, float]]) -> None:
        import numpy as np

        all_keys = set()
        for f in feature_vectors:
            all_keys.update(f.keys())

        self._normalization_params = {}
        for key in all_keys:
            values = [f.get(key, 0.0) for f in feature_vectors]
            self._normalization_params[key] = (float(np.mean(values)), float(np.std(values)))

    def compute_flow_statistics(self, packets: List[Dict]) -> Dict[str, float]:
        if not packets:
            return {}

        lengths = [p.get("length", 0) for p in packets]
        intervals = []
        for i in range(1, len(packets)):
            dt = packets[i].get("timestamp", 0) - packets[i-1].get("timestamp", 0)
            intervals.append(dt)

        return {
            "total_packets": len(packets),
            "total_bytes": sum(lengths),
            "avg_length": float(np.mean(lengths)) if lengths else 0,
            "std_length": float(np.std(lengths)) if lengths else 0,
            "min_length": float(min(lengths)) if lengths else 0,
            "max_length": float(max(lengths)) if lengths else 0,
            "avg_interval": float(np.mean(intervals)) if intervals else 0,
            "std_interval": float(np.std(intervals)) if intervals else 0,
        }

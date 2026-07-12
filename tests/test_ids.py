from src.ids.engine import NeuralIDS, ClassificationResult, ATTACK_TYPES
from src.features.extractor import FeatureExtractor


def test_heuristic_dos_detection():
    ids = NeuralIDS()
    features = {
        "packets": 5000,
        "bytes": 2000000,
        "duration": 1.0,
        "src_port": 12345,
        "dst_port": 80,
        "protocol": 6,
        "flags_syn": 1.0,
        "flags_ack": 0.0,
    }
    result = ids.classify(features)
    assert result.attack_type == "DoS"
    assert result.is_attack is True


def test_normal_traffic():
    ids = NeuralIDS()
    features = {
        "packets": 10,
        "bytes": 5000,
        "duration": 10.0,
        "src_port": 49152,
        "dst_port": 443,
        "protocol": 6,
        "flags_syn": 0.0,
        "flags_ack": 1.0,
    }
    result = ids.classify(features)
    assert result.attack_type == "Normal"
    assert result.is_attack is False


def test_result_to_dict():
    ids = NeuralIDS()
    result = ids.classify({"packets": 100, "bytes": 5000, "duration": 2.0, "dst_port": 80})
    d = result.to_dict()
    assert "attack_type" in d
    assert "confidence" in d
    assert "is_attack" in d


def test_feature_extractor():
    extractor = FeatureExtractor()
    flow = {"packets": 100, "bytes": 5000, "duration": 2.0, "flags": "SYN,ACK"}
    features = extractor.extract(flow)
    assert features["packets"] == 100.0
    assert features["flags_syn"] == 1.0
    assert features["flags_ack"] == 1.0


def test_alert_creation():
    ids = NeuralIDS()
    features = {"packets": 5000, "bytes": 2000000, "duration": 0.5, "flags_syn": 1.0}
    result = ids.classify(features)
    alert = ids.create_alert(result, "10.0.0.1", "192.168.1.1")
    if result.is_attack:
        assert alert is not None
        assert alert.attack_type == result.attack_type


def test_stats():
    ids = NeuralIDS()
    stats = ids.get_stats()
    assert "total_alerts" in stats
    assert "models_loaded" in stats

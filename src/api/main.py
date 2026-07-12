from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

app = FastAPI(
    title="Neural IDS API",
    description="Neural network-based Intrusion Detection System",
    version="1.0.0",
)

_ids = None


def _get_ids():
    global _ids
    if _ids is None:
        from src.ids.engine import NeuralIDS
        import os
        _ids = NeuralIDS(model_dir=os.getenv("MODEL_DIR", "models/"))
    return _ids


class FlowInput(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 6
    packets: int = 0
    bytes: int = 0
    duration: float = 0.0
    flags: str = ""


class ClassificationResponse(BaseModel):
    attack_type: str
    confidence: float
    is_attack: bool
    model_scores: Dict[str, float]
    severity: str


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/v1/classify", response_model=ClassificationResponse)
async def classify(flow: FlowInput):
    ids = _get_ids()
    from src.features.extractor import FeatureExtractor
    extractor = FeatureExtractor()
    features = extractor.extract(flow.model_dump())
    result = ids.classify(features)

    if result.is_attack:
        ids.create_alert(result, flow.src_ip, flow.dst_ip)

    return ClassificationResponse(**result.to_dict())


@app.get("/api/v1/alerts")
async def list_alerts(limit: int = 100, severity: Optional[str] = None):
    ids = _get_ids()
    alerts = ids.get_alerts(limit=limit, severity=severity)
    return {"alerts": [a.to_dict() for a in alerts], "count": len(alerts)}


@app.get("/api/v1/stats")
async def stats():
    ids = _get_ids()
    return ids.get_stats()


@app.get("/api/v1/models")
async def model_info():
    return {
        "models": {
            "lstm": {"type": "LSTM", "input_size": 8, "hidden_size": 128, "num_classes": 5},
            "cnn": {"type": "CNN", "input_size": 8, "filters": 64, "num_classes": 5},
        },
        "ensemble_weights": {"lstm": 0.5, "cnn": 0.5},
        "attack_types": ["Normal", "DoS", "Probe", "U2R", "R2L"],
    }

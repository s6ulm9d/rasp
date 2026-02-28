from fastapi import FastAPI
from pydantic import BaseModel
import onnxruntime as ort
import numpy as np

app = FastAPI(title="ShieldRASP ML Inference API")

# Load ONNX model at startup (dummy path for structure)
# session = ort.InferenceSession("models/isolation_forest.onnx")

class ScoreRequest(BaseModel):
    event_type: str
    taint_path: str
    endpoint: str
    user_id: str
    session_request_count: int
    time_since_last_request: float
    query_structure_hash: str
    app_id: str

@app.post("/score")
async def score_event(req: ScoreRequest):
    # Minimal feature extraction
    features = np.array([[
        req.session_request_count,
        req.time_since_last_request
    ]], dtype=np.float32)

    return {
        "anomaly_score": 0.95,
        "is_anomaly": True,
        "confidence": 0.92
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

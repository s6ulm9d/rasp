from confluent_kafka import Consumer, Producer
import json
import requests
import os

KAFKA_BROKERS = os.environ.get("KAFKA_BROKERS", "localhost:9092")
ML_API = "http://localhost:8000/score"

c = Consumer({
    'bootstrap.servers': KAFKA_BROKERS,
    'group.id': 'ml-scorer',
    'auto.offset.reset': 'latest'
})
p = Producer({'bootstrap.servers': KAFKA_BROKERS})

c.subscribe(['rasp.events.raw'])

def run_loop():
    while True:
        msg = c.poll(1.0)
        if msg is None: continue
        if msg.error(): continue

        event = json.loads(msg.value().decode('utf-8'))
        
        # Call Inference API
        req_data = {
            "event_type": event.get("attack_type", "unknown"),
            "taint_path": event.get("taint_path", ""),
            "endpoint": event.get("http_path", ""),
            "user_id": event.get("user_id", ""),
            "session_request_count": 10,
            "time_since_last_request": 0.5,
            "query_structure_hash": "hash123",
            "app_id": event.get("service_name", "")
        }
        
        try:
            res = requests.post(ML_API, json=req_data).json()
            event["ml_anomaly_score"] = res["anomaly_score"]
            event["ml_is_anomaly"] = res["is_anomaly"]
            
            p.produce('rasp.events.scored', json.dumps(event).encode('utf-8'))
            p.poll(0)
        except Exception as e:
            print("ML scoring failed:", e)

if __name__ == "__main__":
    run_loop()

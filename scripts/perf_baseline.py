import time, statistics
import httpx

URLS = [
    ("login", "POST", "http://localhost:8000/api/v1/auth/login"),
    ("health", "GET", "http://localhost:8000/health"),
    ("dashboard", "GET", "http://localhost:8000/api/v1/dashboard/summary"),
]

def bench(url, method="GET", payload=None, concurrency=5, iterations=20):
    times = []
    errors = 0
    for _ in range(iterations):
        start = time.time()
        try:
            if method == "POST":
                r = httpx.post(url, json=payload or {}, timeout=5)
            else:
                r = httpx.get(url, timeout=5)
            if r.status_code >= 400:
                errors += 1
        except Exception:
            errors += 1
        times.append((time.time() - start)*1000)
    return {"p50": statistics.median(times), "p95": sorted(times)[int(len(times)*0.95)] if times else 0, "error_rate": errors/iterations*100, "avg": statistics.mean(times) if times else 0}

if __name__ == "__main__":
    for name, method, url in URLS:
        res = bench(url, method)
        print(f"{name}: p50={res['p50']:.1f}ms p95={res['p95']:.1f}ms error={res['error_rate']:.1f}%")

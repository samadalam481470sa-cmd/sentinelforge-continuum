"""Low-overhead HTTP hardening and aggregate telemetry."""
from __future__ import annotations

import hmac
import os
import time
from collections import Counter, defaultdict, deque
from threading import Lock

from fastapi import HTTPException, Request
from fastapi.responses import PlainTextResponse

_lock = Lock()
_requests: Counter[tuple[str, int]] = Counter()
_rate: dict[str, deque[float]] = defaultdict(deque)


async def security_middleware(request: Request, call_next):
    maximum = int(os.getenv("SENTINELFORGE_MAX_BODY_BYTES", "1048576"))
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > maximum:
                raise HTTPException(status_code=413, detail="Request body too large")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid content length") from exc

    # Coarse per-client limiter for the prototype; production should use gateway-level limits.
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    limit = int(os.getenv("SENTINELFORGE_RATE_LIMIT_PER_MINUTE", "120"))
    with _lock:
        bucket = _rate[client]
        while bucket and now - bucket[0] > 60:
            bucket.popleft()
        if len(bucket) >= limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        bucket.append(now)

    response = await call_next(request)
    with _lock:
        _requests[(request.method, response.status_code)] += 1
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


def metrics(request: Request):
    expected = os.getenv("SENTINELFORGE_METRICS_TOKEN")
    if not expected:
        raise HTTPException(status_code=404, detail="Metrics disabled")
    supplied = request.headers.get("X-Metrics-Token", "")
    if not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=401, detail="Unauthorized")
    with _lock:
        snapshot = list(_requests.items())
    lines = [
        "# HELP sentinelforge_http_requests_total HTTP requests by method and status",
        "# TYPE sentinelforge_http_requests_total counter",
    ]
    for (method, status), count in snapshot:
        lines.append(
            f'sentinelforge_http_requests_total{{method="{method}",status="{status}"}} {count}'
        )
    return PlainTextResponse("\n".join(lines) + "\n")

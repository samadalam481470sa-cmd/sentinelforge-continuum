"""Minimal security response middleware and health counters."""
from collections import Counter

counts = Counter()


async def record(request, call_next):
    response = await call_next(request)
    counts[(request.method, response.status_code)] += 1
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

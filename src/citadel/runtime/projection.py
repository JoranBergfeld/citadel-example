"""Common bounded policy envelope for team-owned Operator observations."""

import math

from starlette.responses import JSONResponse

from citadel.operations import OperationError, identity
from .state import read_deadline


MAX_RESPONSE_BYTES = 262144


async def respond(runtime, request, function, *args, missing="missing"):
    try:
        if runtime.observation_reads is None:
            raise OperationError("unavailable", "Deployment observation admission unavailable")
        end = float(request.headers.get("x-citadel-observation-deadline", runtime.clock() + 30))
        if not math.isfinite(end):
            raise ValueError("Invalid deadline")
        async with runtime.observation_reads.request(deadline=end):
            identity(args[0])
            result = await function(*args)
            result["activity"] = runtime.activity.observe(args[0])
            response = JSONResponse(result)
            if runtime.clock() >= read_deadline.get():
                raise OperationError("deadline", "Observation deadline expired")
            if len(response.body) > MAX_RESPONSE_BYTES:
                raise OperationError("result_limit", "Saved projection exceeds response bound")
            return response
    except OperationError as exc:
        state = {"forbidden": "denied", "not_found": "missing", "missing": missing,
                 "exhausted": "exhausted"}.get(exc.code, "unavailable")
        return JSONResponse({"state": state}, status_code={
            "denied": 403, "missing": 404, "exhausted": 429}.get(state, 503))
    except (TimeoutError, KeyError, TypeError, ValueError, OverflowError):
        return JSONResponse({"state": "unavailable"}, status_code=503)

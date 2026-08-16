# Failure cases

| Failure | Expected/user-visible/log/recovery | Test |
|---|---|---|
| broker unavailable/restart/DNS failure | agent logs bounded error, exponential jittered reconnect; active TCP fails, new traffic resumes after registry restore | failure reconnect run |
| FastAPI unavailable/restart | existing C relays continue; creation/readiness fail; API restores unexpired registry | process isolation run |
| SQLite unavailable/disk full | API readiness/mutations fail without broker crash; operator repairs storage | API failure test |
| local service unavailable/closes early | one stream gets FIN/reset; tunnel remains online | integration half-close |
| agent/public/closed peer disconnect, RST | affected flow closes and buffers free; agent reconnects for new streams | integration + sanitizer |
| closed wrong token | indistinguishable auth rejection, no service bytes, failed-auth counter | closed TCP integration |
| expired/disabled/deleted tunnel | listeners close, agent drops, announcements disable, port releases | API/integration deletion |
| port collision/exhaustion | deterministic create error, no arbitrary bind | broker IPC test |
| invalid/expired certificate | verified client refuses; explicit operator action required | manual TLS test |
| malformed/oversized frame | connection closes, protocol metric increments, process stays alive | C parser tests |
| heartbeat timeout/broker IPC unavailable | agent reconnect or readiness 503; structured event | failure/API tests |
| slow peer/service/low memory/FD limit/flood | bounded queues and rate/global limits reject/drop; no unbounded growth | constrained load test |
| 5+ GiB stream | generated streaming bytes, no disk, hash matches | extended `large_stream.py` |
| client/server half-close | queued tail drains before FIN; reverse direction remains available | TCP integration |
| announcement duplicate/invalid URL | stable IDs allow multiples; malformed URL gets 422 | API tests |
| SIGTERM | stop accepts, GOING_AWAY, grace, close; SIGKILL is abrupt | sanitizer fixture |

`journalctl` contains metadata and error codes only, never credentials or
payloads. Automatic recovery never pretends interrupted TCP can resume.

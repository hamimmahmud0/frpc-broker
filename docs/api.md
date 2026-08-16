# HTTP API

The live OpenAPI document is `/openapi.json`; Swagger and ReDoc are `/docs` and
`/redoc`. Errors use `{"error":{"code","message","request_id"}}`.

- `POST /v1/tunnels`: anonymous TCP/UDP open/closed creation.
- `GET|PATCH|DELETE /v1/tunnels/{id}`: owner operations using
  `X-Tunnel-Management-Secret`.
- `POST /v1/tunnels/{id}/renew|rotate-token|rotate-agent-secret`.
- `POST /v1/announce`, `GET /v1/announce[/search|/{id}]`, and owner
  `PATCH|DELETE /v1/announce/{id}`.
- `GET /health/live`, `/health/ready`, `/v1/status`, and `/llms.txt`.
- `/v1/admin/*`: cookie-authenticated operations requiring `X-CSRF-Token` on
  mutations; includes tunnels, streams, announcements, topology, and CIDR
  blocks.

Creation returns agent, management, and (for closed mode) shared capabilities
once. There is deliberately no global creation credential.

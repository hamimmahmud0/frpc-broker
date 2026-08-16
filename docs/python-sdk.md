# Python SDK

`tunnelmate.new(url, dict_or_TunnelConfig)` creates a `Tunnel`. Lifecycle:
`announce`, `unannounce`, `start`, `stop`, `wait`, `status`, `stats`, `renew`,
`rotate_token`, and `delete`. The SDK launches the C agent using a temporary
0600 config and removes it on stop. `tunnelmate.connect(...)` similarly starts
the C peer with a 0600 token file.

`set_message_handler(handler)` opts TCP into a local Python proxy. The handler
receives `(direction, chunk, context)` and returns bytes or `None`. Chunks are
not application messages; changing them can break the application protocol.
Leave handlers disabled for large/high-throughput transfers so payloads remain
on the C fast path.

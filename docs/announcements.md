# Announcements

Announcements belong to a tunnel and derive protocol, scope, and peer address
from it. Owners provide `service_name`, stable `service_id`, an HTTP(S)
`llms` URL, and generic JSON `attributes`. Attribute bytes, depth, keys, and URL
length are bounded. The server never fetches `llms`, avoiding an SSRF oracle.

Search accepts `service`, `service_id`, `scope`, `protocol`, `tunnel_id`, and
`attribute.NAME=value`. Online state is derived from the broker; metadata
survives temporary agent disconnects. HTML templates escape metadata.

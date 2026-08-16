# NAT namespace scenario

Create three Linux network namespaces (peer, broker, private), join them with
veth pairs, enable forwarding only on the broker-facing NAT router, and apply a
MASQUERADE rule for private egress. Start the local service and agent in the
private namespace, broker on the public namespace, and peer on the peer
namespace. Assert a direct connection to the private address fails while the
allocated broker TCP/UDP port succeeds. This is an opt-in root test; the normal
integration suite exercises the same outbound-only agent topology on loopback.

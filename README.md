# Experimental simplified DTLS packet transport interface

*Disclaimer:* This is not an officially supported Google product.

## Objective

Create a simple interface that allows private and authenticated transport of
packet between multiple peers. Peers are identified and authenticated only by
their fingerprints.

Implement in Rust.

# Background

Using SSL correctly is notoriously diffucult and involves certificate
management, DNS etc. However, in many cases identity based on host names is not
needed. Instead it can be established more directly using the fingerprints of
public keys. In such a case establishing a secure channel can become much
simpler.

## Design ideas

This layer takes care just of peer authentication. All actual network transport
is done by an underlying layer, to which addresses are passed unchanged.

Each node is equipped with a SSL asymmetric encryption key. The node is
identified among others by the fingerprint of this key.

The underlying transport layer must be capable of:

1. Routing packets towards a target node given its address.

2. Obtaining the public key of a node given its address.

### Opening a connection

For creating a connection from a source to a target node, the source node needs
only the target’s address and fingerprint.

First, it asks the underlying layer to retrieve the target’s public key and
verifies it against the fingerprint. This needs to be done only once, the keys
can be cached indefinitely, if desired.

Then it uses DTLS and the target's public key to create a secure connection to
target using the obtained key, using the underlying layer’s communication
mechanism.

Similarly, upon receiving a request, the target node is able to verify the
authenticity of the source node if desired (requesting its public key, if
needed).

Afterwards the communication of individual packets is simply handed over to
DTLS.

## Proposed API

Available to the library’s user:

- CreateConnection(address, target_fingerprint) -> handle
- Listen() -> listen_handle
- Accept(listen_handle) -> (handle, source_fingerprint)
- CloseConnection(handle)
- SendPacket(handle, bytes)
- ReceivePacket(handle) -> bytes  // alternatively using a callback

Required from the underlying layer:

- SendPacket(address, bytes)
- ReceivePacket(address) -> bytes
- ObtainPublicKey(address) -> bytes

## References

- [DTLS with OpenSSL](http://chris-wood.github.io/2016/05/06/OpenSSL-DTLS.html)

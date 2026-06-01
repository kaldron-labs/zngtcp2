zngtcp2 Buffer Contract
=======================

zngtcp2 is a private fork API.  Source compatibility with upstream ngtcp2 is
not a target for installed headers, package names, or crypto provider
selection.

Installed public headers use ``zngtcp2/...`` include paths.  C symbols keep the
``ngtcp2_`` and ``NGTCP2_`` prefixes.

Buffer Lifetime
---------------

Data-path APIs use ``ngtcp2_buf`` to describe byte ranges, ownership, and
semantic role.

``origin`` is ``NULL`` for library/internal storage.  Non-``NULL`` values are
opaque application or allocator identities and are compared only by pointer
value.

``role`` identifies the semantic use of the bytes.  Public UDP receive input is
``NGTCP2_BUF_ROLE_RX_PACKET``.  Library-owned UDP transmit handoffs are
``NGTCP2_BUF_ROLE_TX_PACKET``.  Stream and DATAGRAM application payload buffers
use ``NGTCP2_BUF_ROLE_TX_STREAM`` and ``NGTCP2_BUF_ROLE_TX_DATAGRAM``.
Callback-visible receive spans use ``NGTCP2_BUF_ROLE_RX_STREAM``,
``NGTCP2_BUF_ROLE_RX_CONTROL``, or ``NGTCP2_BUF_ROLE_RX_DATAGRAM``.

If ownership escapes a call, zngtcp2 must retain the owner through the buffer
callbacks and release it exactly once after the protocol no longer needs the
bytes.

Callback Signatures
-------------------

The fork replaces data-path callbacks in place.  Legacy raw-pointer callback
compatibility is not a supported API goal.

``recv_crypto_data`` and ``recv_stream_data`` receive ``ngtcp2_buf`` callback
buffers.  Callback-visible receive buffers have a role matching the delivered
data, such as ``RX_CONTROL`` or ``RX_STREAM``.

``ngtcp2_crypto_ops`` uses source-to-destination packet protection.  TX packet
protection receives plaintext vectors plus ``ngtcp2_buf`` AAD, nonce, and mask
arguments.  RX packet unprotection writes plaintext to storage distinct from the
UDP ciphertext packet.  Header-protection fallback receives ``ngtcp2_buf``
sample and destination mask buffers.  Retry protection receives ``ngtcp2_buf``
plaintext, nonce, and AAD buffers.  Implementations must not stage raw-pointer
compatibility shims that hide data-path copies.

CRYPTO Transmit
---------------

``ngtcp2_conn_submit_crypto_data`` accepts ``crypto_tx`` buffers.  If a
non-borrowed buffer has retain/release owner callbacks, zngtcp2 retains the
owner and queues the referenced range directly.  Borrowed or ownerless buffers
take the internal copy path and do not satisfy the target retained-provider
invariant.

zpicotls writes TLS handshake output into a pre-provisioned, provider-owned
``crypto_tx`` buffer.  Each QUIC encryption-level span submitted from that
buffer carries the same retained owner.  zpicotls-origin ``ptls_buffer_t``
growth is a forbidden staging copy on the target path; it records
``zpicotls_crypto_staging_copy`` and fails with
``NGTCP2_ERR_BUF_CONTRACT``.

Error Behavior
--------------

Buffer contract violations return ``NGTCP2_ERR_BUF_CONTRACT``.  This includes
wrong role, unsupported origin, missing zpicotls packet crypto ops on the
buffer API path, and target-forbidden fallback copies.

``NGTCP2_ERR_BUF_CONTRACT`` is fatal and maps to QUIC
``NGTCP2_INTERNAL_ERROR``.

Copy Counters
-------------

Forbidden target-path counters:

* ``rx_pkt_copy``
* ``decrypt_buf_use``
* ``zpicotls_full_pkt_copy_attempt``
* ``zpicotls_crypto_staging_copy``

Allowed and counted copies:

* ``rx_trailing_copy`` for coalesced datagram trailing bytes
* ``rx_mixed_stream_copy`` for later STREAM frames in a mixed packet
* ``reorder_copy`` for fragmentation or overlap normalization

Current Phase Checkpoints
-------------------------

The installed packet receive, app payload submit, ``recv_crypto_data``, and
``recv_stream_data`` surfaces use buffer signatures.  ``ngtcp2_crypto_ops``
packet protection uses plaintext vectors for TX and distinct destination
storage for RX.  Retry protection and header-protection callbacks use
``ngtcp2_buf`` for data-path byte ranges.  Raw pointer and legacy packet
construction entry points are transitional internals used only while migrating
library tests and examples.

Public STREAM transmit allocates zngtcp2-issued ``TX_STREAM`` buffers.  The
application fills the uninitialized payload and submits the filled prefix.
zngtcp2 retains accepted bytes in the STREAM frame chain and releases them
after ACK accounting, retransmission cleanup, stream teardown, or connection
deletion.  Reclaimed and split STREAM frame chains take their own owner retain
so every frame-chain lifetime has a matching release.

Public DATAGRAM transmit allocates zngtcp2-issued ``TX_DATAGRAM`` buffers.  The
application fills and submits one DATAGRAM payload.  zngtcp2 retains the
payload until packet protection succeeds, then keeps only DATAGRAM metadata
needed for ACK/loss callbacks.

Public STREAM transmit emits one semantic non-PADDING STREAM frame for one
stream in a stream-data packet.  PADDING remains valid only where QUIC requires
it or where the packet API explicitly requests it.

The target receive path removes header protection from packet header bytes but
writes AEAD plaintext into zngtcp2-owned storage distinct from the UDP
ciphertext packet.  Packet receive/write entry points that require packet
protection fail with ``NGTCP2_ERR_REQUIRED_CALLBACK`` when provider ops are
missing.

Target packet transmit encrypts generated control fragments and retained
STREAM/DATAGRAM payload vectors directly into zngtcp2-owned ``TX_PACKET``
handoff buffers through ``ngtcp2_crypto_ops.protect_pkt``.  Successful packet
protection increments ``encrypt_source_to_dest_success``; provider contract
failures increment ``encrypt_source_to_dest_failure`` and return
``NGTCP2_ERR_BUF_CONTRACT``.

Provider CRYPTO transmit uses retained ``crypto_tx`` buffers.  zpicotls keeps
handshake output in provider-owned storage and hands retained spans to the
connection; queued CRYPTO frames release those spans when acknowledged,
retransmitted and discarded, or deleted with the connection.

The target public receive path exposes STREAM, CRYPTO/control, and DATAGRAM
data as role-appropriate ``ngtcp2_buf`` spans over decrypted plaintext storage.
Callbacks never receive STREAM or DATAGRAM spans whose lifetime depends on the
UDP ciphertext packet buffer.

Coalesced target receive keeps the current packet in the caller-owned datagram
buffer and copies trailing future packet bytes through the configured
data-path allocator before callbacks can expose current-packet ownership.  The
copied byte count is recorded in ``rx_trailing_copy``.  Missing allocator
support or allocator policy rejection returns ``NGTCP2_ERR_BUF_CONTRACT``.

Out-of-order STREAM and CRYPTO receive on the public buffer path use
role-appropriate plaintext reorder storage.  Decrypted backing storage is
retained when it can safely cover the offset gap; otherwise the data is copied
through the configured allocator and counted in ``reorder_copy``.  Internal
transitional paths still count legacy byte-copy reorder buffer use in
``reorder_copy``.

Rebase Checklist
----------------

Before rebasing on upstream ngtcp2:

* verify installed headers stay under ``include/zngtcp2``;
* verify pkg-config modules and installed libraries use ``libzngtcp2`` names;
* verify zpicotls remains the only enabled provider build target;
* verify ``ngtcp2_crypto_ops`` signatures remain vector TX and distinct
  source/destination RX, with ``ngtcp2_buf`` based AAD, nonce, HP sample/mask,
  and Retry inputs;
* verify retained ``crypto_tx`` submission is still used for zpicotls handshake
  output and retransmission;
* run protocol tests and check buffer counters for forbidden target-path copies;
* run packet and reorder fuzzers with receive/transmit buffer entry points and
  retain/release balance assertions;
* rerun public installed-header smoke tests for hidden raw STREAM vector APIs;
* rerun zpicotls provider compile and packet crypto alias tests.

Rename Checklist
----------------

Reject stale installed ``ngtcp2`` package names, include directories, CMake
package names, and pkg-config modules unless they are deliberate source-level C
symbol references.

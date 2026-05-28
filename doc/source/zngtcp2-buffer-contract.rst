zngtcp2 Buffer Contract
=======================

zngtcp2 is a private fork API.  Source compatibility with upstream ngtcp2 is
not a target for installed headers, package names, or crypto provider
selection.

Installed public headers use ``zngtcp2/...`` include paths.  C symbols keep the
``ngtcp2_`` and ``NGTCP2_`` prefixes.

Buffer Lifetime
---------------

Data-path APIs use ``ngtcp2_buf`` to describe byte ranges, ownership, direction,
and purpose.

``origin`` identifies who owns the bytes.  Target packet and stream public APIs
accept application-origin buffers.  Borrowed buffers cannot be retained.

``dir`` is one of internal, receive, or transmit.  Public receive packet input
must be ``NGTCP2_BUF_DIR_RX``.  Public packet and stream transmit buffers must
be ``NGTCP2_BUF_DIR_TX``.

``purpose`` identifies the semantic use of the bytes.  Public packet receive
input must be ``NGTCP2_BUF_PURPOSE_PACKET_RX``.  Public packet transmit output
must be ``NGTCP2_BUF_PURPOSE_PACKET_TX``.  Public stream transmit data must be
``NGTCP2_BUF_PURPOSE_STREAM_TX``.

If ownership escapes a call, zngtcp2 must retain the owner through the buffer
callbacks and release it exactly once after the protocol no longer needs the
bytes.

Error Behavior
--------------

Buffer contract violations return ``NGTCP2_ERR_BUF_CONTRACT``.  This includes
wrong direction, wrong purpose, unsupported origin, missing zpicotls packet
crypto ops on the buffer API path, and target-forbidden fallback copies.

``NGTCP2_ERR_BUF_CONTRACT`` is fatal and maps to QUIC
``NGTCP2_INTERNAL_ERROR``.

Copy Counters
-------------

Forbidden target-path counters:

* ``decrypt_buf_use``
* ``rx_pkt_copy``
* ``zpicotls_full_pkt_copy_attempt``
* ``zpicotls_crypto_staging_copy``

Allowed and counted copies:

* ``rx_trailing_copy`` for coalesced datagram trailing bytes
* ``rx_mixed_stream_copy`` for later STREAM frames in a mixed packet
* ``reorder_copy`` for fragmentation or overlap normalization

Current Phase Checkpoints
-------------------------

The installed packet receive, stream transmit, ``recv_crypto_data``, and
``recv_stream_data`` surfaces use buffer signatures by default.  The raw pointer
and vectored STREAM send API is available only while building the library or
tests.

The target receive path decrypts header protection and payloads in place when
zpicotls packet crypto ops are installed.  Internal legacy tests without
provider ops fall back to the legacy decrypt buffer and increment
``decrypt_buf_use``.

The target public receive path exposes first STREAM frames and CRYPTO data as
``ngtcp2_buf`` callback buffers.  If the packet buffer has retain/release owner
callbacks, zngtcp2 retains the packet owner for the callback and releases it
after the callback returns.  Later STREAM frames in the same packet require the
configured data-path allocator and are counted in ``rx_mixed_stream_copy``.

Coalesced target receive currently fails closed if a long-header datagram has
trailing bytes.  It counts the trailing length in ``rx_trailing_copy`` and
returns ``NGTCP2_ERR_BUF_CONTRACT`` until the full copy-and-replay path is
implemented.

Rebase Checklist
----------------

Before rebasing on upstream ngtcp2:

* verify installed headers stay under ``include/zngtcp2``;
* verify pkg-config modules and installed libraries use ``libzngtcp2`` names;
* verify unsupported provider build targets are not enabled by default;
* run protocol tests and check buffer counters for forbidden target-path copies;
* rerun public installed-header smoke tests for hidden raw STREAM vector APIs;
* rerun zpicotls provider compile and packet crypto alias tests.

Rename Checklist
----------------

Reject stale installed ``ngtcp2`` package names, include directories, CMake
package names, and pkg-config modules unless they are deliberate source-level C
symbol references.

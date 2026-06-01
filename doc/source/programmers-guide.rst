The ngtcp2 programmers' guide
=============================

This document describes a brief introduction of programming ngtcp2.

Prerequisites
-------------

Reading :rfc:`9000` and :rfc:`9001` helps you a lot to write QUIC
application.  They describes how TLS is integrated into QUIC and why
the existing TLS stack cannot be used with QUIC.

QUIC requires a special interface from the TLS stack.  zngtcp2
supports zpicotls through the ``libzngtcp2_crypto_zpicotls`` helper
library.

Creating ngtcp2_conn object
---------------------------

:type:`ngtcp2_conn` is the primary object to present a single QUIC
connection.  Use `ngtcp2_conn_client_new()` for client application,
and `ngtcp2_conn_server_new()` for server.

They require :type:`ngtcp2_callbacks`, :type:`ngtcp2_settings`, and
:type:`ngtcp2_transport_params` objects.

The :type:`ngtcp2_callbacks` contains the callback functions which
:type:`ngtcp2_conn` calls when a specific event happens, say,
receiving stream data or stream is closed, etc.  Some of the callback
functions are optional.  For client application, the following
callback functions must be set:

* :member:`client_initial <ngtcp2_callbacks.client_initial>`:
  `ngtcp2_crypto_client_initial_cb()` can be passed directly.
* :member:`recv_crypto_data <ngtcp2_callbacks.recv_crypto_data>`:
  `ngtcp2_crypto_recv_crypto_data_cb()` can be passed directly.
* :member:`recv_retry <ngtcp2_callbacks.recv_retry>`:
  `ngtcp2_crypto_recv_retry_cb()` can be passed directly.
* :member:`rand <ngtcp2_callbacks.rand>`
* :member:`get_new_connection_id2
  <ngtcp2_callbacks.get_new_connection_id2>`
* :member:`update_key <ngtcp2_callbacks.update_key>`:
  `ngtcp2_crypto_update_key_cb()` can be passed directly.
* :member:`delete_crypto_aead_ctx
  <ngtcp2_callbacks.delete_crypto_aead_ctx>`:
  `ngtcp2_crypto_delete_crypto_aead_ctx_cb()` can be passed directly.
* :member:`delete_crypto_cipher_ctx
  <ngtcp2_callbacks.delete_crypto_cipher_ctx>`:
  `ngtcp2_crypto_delete_crypto_cipher_ctx_cb()` can be passed
  directly.
* :member:`get_path_challenge_data2
  <ngtcp2_callbacks.get_path_challenge_data2>`:
  `ngtcp2_crypto_get_path_challenge_data2_cb()` can be passed directly.
* :member:`version_negotiation
  <ngtcp2_callbacks.version_negotiation>`:
  `ngtcp2_crypto_version_negotiation_cb()` can be passed directly.

For server application, the following callback functions must be set:

* :member:`recv_client_initial
  <ngtcp2_callbacks.recv_client_initial>`:
  `ngtcp2_crypto_recv_client_initial_cb()` can be passed directly.
* :member:`recv_crypto_data <ngtcp2_callbacks.recv_crypto_data>`:
  `ngtcp2_crypto_recv_crypto_data_cb()` can be passed directly.
* :member:`rand <ngtcp2_callbacks.rand>`
* :member:`get_new_connection_id2
  <ngtcp2_callbacks.get_new_connection_id2>`
* :member:`update_key <ngtcp2_callbacks.update_key>`:
  `ngtcp2_crypto_update_key_cb()` can be passed directly.
* :member:`delete_crypto_aead_ctx
  <ngtcp2_callbacks.delete_crypto_aead_ctx>`:
  `ngtcp2_crypto_delete_crypto_aead_ctx_cb()` can be passed directly.
* :member:`delete_crypto_cipher_ctx
  <ngtcp2_callbacks.delete_crypto_cipher_ctx>`:
  `ngtcp2_crypto_delete_crypto_cipher_ctx_cb()` can be passed
  directly.
* :member:`get_path_challenge_data2
  <ngtcp2_callbacks.get_path_challenge_data2>`:
  `ngtcp2_crypto_get_path_challenge_data2_cb()` can be passed directly.
* :member:`version_negotiation
  <ngtcp2_callbacks.version_negotiation>`:
  `ngtcp2_crypto_version_negotiation_cb()` can be passed directly.

``ngtcp2_crypto_*`` functions are a part of :doc:`ngtcp2 crypto API
<crypto_apiref>` which provides easy integration with the supported
TLS backend.  It vastly simplifies TLS integration and is strongly
recommended.

:type:`ngtcp2_settings` contains the settings for QUIC connection.
All fields must be set.  Application should call
`ngtcp2_settings_default()` to set the default values.  It would be
very useful to enable debug logging by setting logging function to
:member:`ngtcp2_settings.log_printf` field.  ngtcp2 library relies on
the timestamp fed from application.  The initial timestamp must be
passed to :member:`ngtcp2_settings.initial_ts` field in nanosecond
resolution.  ngtcp2 cares about the difference from that initial
value.  It could be any timestamp which increases monotonically, and
actual value does not matter.

:type:`ngtcp2_transport_params` contains QUIC transport parameters
which is sent to a remote endpoint during handshake.  Application
should call `ngtcp2_transport_params_default()` to set the default
values.  Server must set
:member:`ngtcp2_transport_params.original_dcid` and set
:member:`ngtcp2_transport_params.original_dcid_present` to nonzero.

Client application has to supply Connection IDs to
`ngtcp2_conn_client_new()`.  The *dcid* parameter is the destination
connection ID (DCID), and which should be random byte string and at
least 8 bytes long.  The *scid* is the source connection ID (SCID)
which identifies the client itself.  The *client_chosen_version*
parameter is the QUIC version to use.  It should be
:macro:`NGTCP2_PROTO_VER_V1`.

Similarly, server application has to supply these parameters to
`ngtcp2_conn_server_new()`.  But the *dcid* must be the same value
which is received from client (which is client SCID).  The *scid* is
chosen by server.  Don't use DCID in client packet as server SCID.
The *client_chosen_version* parameter is the QUIC version that client
has chosen.

A path is very important to QUIC connection.  It is the pair of
endpoints, local and remote.  The path passed to
`ngtcp2_conn_client_new()` and `ngtcp2_conn_server_new()` is a network
path that handshake is performed.  The path must not change during
handshake.  After handshake is confirmed, client can migrate to new
path.  An application must provide actual path to the API function to
tell the library where a packet comes from.  The "write" API function
takes path parameter and fills it to which the packet should be sent.

.. _tls-integration:

TLS integration
---------------

Use of :doc:`ngtcp2 crypto API <crypto_apiref>` is strongly
recommended because it vastly simplifies the TLS integration.

The most of the TLS work is done by the callback functions passed to
:type:`ngtcp2_callbacks` object.  There are some operations left to
application in order to make TLS integration work.  We have a set of
helper functions to make it easier for applications to configure TLS
stack object to work with QUIC and ngtcp2.  They are specific to each
supported TLS stack.

They make the minimal QUIC specific changes to the zpicotls objects.
See ``zngtcp2/zngtcp2_crypto_zpicotls.h`` for the provider-specific
API.  In order to make these functions work, we require that a pointer to
:type:`ngtcp2_crypto_conn_ref` must be set as a user data in TLS stack
object, and its :member:`ngtcp2_crypto_conn_ref.get_conn` must point
to a function which returns :type:`ngtcp2_conn` of the underlying QUIC
connection.

zpicotls
~~~~~~~~

The ``ptls_context_t`` object should be configured with one of the
following functions:

* `ngtcp2_crypto_zpicotls_configure_client_context`
* `ngtcp2_crypto_zpicotls_configure_server_context`

For each TLS session, create :type:`ngtcp2_crypto_zpicotls_ctx` object.
It should be initialized by `ngtcp2_crypto_zpicotls_ctx_init`, and
configured with one of the following functions:

* `ngtcp2_crypto_zpicotls_configure_client_session`
* `ngtcp2_crypto_zpicotls_configure_server_session`

The session configuration functions set the
:type:`ngtcp2_crypto_zpicotls_ctx` as the TLS native handle and install
mandatory packet crypto operations.  Applications that need to split setup can
call `ngtcp2_crypto_zpicotls_configure_conn` directly.

:type:`ngtcp2_crypto_conn_ref` must be set as a user data in
``ptls_t`` object inside :type:`ngtcp2_crypto_zpicotls_ctx` via
``ptls_get_data_ptr``.

Configuring TLS stack yourself
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you do not use the above helper functions, you need to generate and
install keys to :type:`ngtcp2_conn`, and pass handshake messages to
:type:`ngtcp2_conn` as well.  When TLS stack generates new secrets,
they have to be installed to :type:`ngtcp2_conn` by calling
`ngtcp2_crypto_derive_and_install_rx_key()` and
`ngtcp2_crypto_derive_and_install_tx_key()`.  When TLS stack generates
new crypto data to send, they must be passed to :type:`ngtcp2_conn` by
calling `ngtcp2_conn_submit_crypto_data()`.

Continue the interrupted TLS handshake
--------------------------------------

Some TLS stacks offer the capability to interrupt TLS handshake to
perform certain operations asynchronously (e.g., private key signing,
certificate lookup).  In general, ngtcp2 does not need to know whether
the TLS handshake is interrupted or not.  In most cases, if the
interruption happens, the TLS handshake function returns the special
error codes.  For supported operations, ngtcp2 crypto helper library
treats them as success (see the above `TLS integration`_ section,
`ngtcp2_crypto_read_write_crypto_data`, and
`ngtcp2_crypto_recv_crypto_data_cb`).  The interrupted handshake is
not restarted automatically.  To continue the handshake, application
should call `ngtcp2_conn_continue_handshake`.

QUIC handshake completion
-------------------------

When QUIC handshake is completed,
:member:`ngtcp2_callbacks.handshake_completed` callback function is
called.  The local and remote endpoint independently declare handshake
completion.  The endpoint has to confirm that the other endpoint also
finished handshake.  When the handshake is confirmed, client side
:type:`ngtcp2_conn` will call
:member:`ngtcp2_callbacks.handshake_confirmed` callback function.
Server confirms handshake when it declares handshake completion,
therefore, separate handshake confirmation callback is not called.

Read and write packets
----------------------

`ngtcp2_conn_read_pkt()` processes the incoming QUIC packets.  In
order to write QUIC packets, submit application payload buffers and
pull protected packet handoffs with `ngtcp2_conn_next_tx_pkt()` or
`ngtcp2_conn_next_tx_pkts()`.  The library allocates packet buffers
through the configured buffer allocator and returns
``NGTCP2_BUF_ROLE_TX_PACKET`` handoff objects to the application.  The
application sends the packet bytes and releases each handoff with
`ngtcp2_conn_release_tx_pkt()`.

In order to send stream data, the application has to first open a
stream.  In earliest, clients can open streams after installing 1RTT
RX(decryption) key, which is notified by
:member:`ngtcp2_callbacks.recv_rx_key`.  Because the key is installed
just before handshake completion, handshake completion (see
:member:`ngtcp2_callbacks.handshake_completed`) is also a good signal
to start opening streams.  For convenience,
:member:`ngtcp2_callbacks.extend_max_local_streams_bidi` and
:member:`ngtcp2_callbacks.extend_max_local_streams_uni` are called
right after :member:`ngtcp2_callbacks.handshake_completed` callback if
there are streams IDs available.

For server, it can open streams after installing 1RTT TX(encryption)
key, which is notified by :member:`ngtcp2_callbacks.recv_tx_key`.
Note that handshake is not authenticated until handshake completes.
Therefore, it is a good practice to send important data after
handshake completion.

Use `ngtcp2_conn_open_bidi_stream()` to open bidirectional
stream.  For unidirectional stream, call
`ngtcp2_conn_open_uni_stream()`.  Call
`ngtcp2_conn_alloc_stream_buf()` to allocate an uninitialized
``TX_STREAM`` payload buffer, fill the submitted bytes, and call
`ngtcp2_conn_submit_stream_buf()` to transfer custody of those bytes
to the library.

An application should pace sending packets.
`ngtcp2_conn_get_send_quantum2()` returns the number of bytes that can
be sent without packet spacing.  After sending one or more packet
handoffs, call `ngtcp2_conn_update_pkt_tx_time()` to set the timer
when the next packet should be sent.  The timer is integrated into
`ngtcp2_conn_get_expiry2()`.

Aggregate packets for GSO
-------------------------

On some platforms, the overhead of sending UDP datagram is far more
expensive than sending TCP packets.  To workaround this, some
platforms offer a function, like GSO in Linux, that accepts multiple
UDP datagrams in 1 system call, and saves the overhead.

To build such a train of packets, call
`ngtcp2_conn_next_tx_pkts()` with an array of
:type:`ngtcp2_tx_pkt`.  The function fills individually owned packet
handoffs and reports a nonzero GSO segment size when the returned
batch is compatible with UDP GSO.  A non-GSO-compatible batch can
still be sent with one UDP send per handoff or a ``sendmmsg`` style
loop.  After sending the batch, release every packet handoff and call
`ngtcp2_conn_update_pkt_tx_time()`.

Outgoing UDP datagram payload size
----------------------------------

The outgoing UDP datagram payload size is 1200 by default.  It may be
increased up to :member:`ngtcp2_settings.max_tx_udp_payload_size` by
Path MTU Discovery (PMTUD).  The PMTUD probes are configurable through
:member:`ngtcp2_settings.pmtud_probes` and
:member:`ngtcp2_settings.pmtud_probeslen`.  If these values are
changed, the largest value should be set to
:member:`ngtcp2_settings.max_tx_udp_payload_size` as well.

Packet handling on server side
------------------------------

Any incoming UDP datagram should be first processed by
`ngtcp2_pkt_decode_version_cid()`.  It can handle Connection ID more
than 20 bytes which is the maximum length defined in QUIC v1.  If the
function returns :macro:`NGTCP2_ERR_VERSION_NEGOTIATION`, server
should send Version Negotiation packet.  Use
`ngtcp2_pkt_next_tx_version_negotiation_pkt()` for this purpose and
release the returned :type:`ngtcp2_tx_pkt` with
`ngtcp2_tx_pkt_release()` after the UDP send completes.  If
`ngtcp2_pkt_decode_version_cid()` succeeds, then check whether the UDP
datagram belongs to any existing connection by looking up connection
tables by Destination Connection ID (refer to the next section to know
how to associate Connection ID to a :type:`ngtcp2_conn`).  If it
belongs to an existing connection, pass the UDP datagram to
`ngtcp2_conn_read_pkt()`.  If it does not belong to any existing
connection, it should be passed to `ngtcp2_accept()`.  If it returns a
negative error code, just drop the packet to the floor and take no
action, or send Stateless Reset packet (use
`ngtcp2_pkt_next_tx_stateless_reset_pkt()` to create a handoff).
Otherwise, the UDP datagram is acceptable as a new
connection.  Create :type:`ngtcp2_conn` object and pass the UDP
datagram to `ngtcp2_conn_read_pkt()`.

Associating Connection ID to ngtcp2_conn
----------------------------------------

Server needs to route an incoming UDP datagram to the correct
:type:`ngtcp2_conn` by its Destination Connection ID.  When a UDP
datagram is received, and it does not belong to any existing
connections, and it is successfully processed by
`ngtcp2_conn_read_pkt()`, associate the Destination Connection ID in
the QUIC packet and :type:`ngtcp2_conn` object.  The server must
associate the Connection IDs returned by `ngtcp2_conn_get_scid2()` to
the :type:`ngtcp2_conn` object as well.  When new Connection ID is
asked by the library,
:member:`ngtcp2_callbacks.get_new_connection_id2` is called.  Inside
the callback, associate the newly generated Connection ID to the
:type:`ngtcp2_conn` object.

When Connection ID is no longer used, its association should be
removed.  When Connection ID is retired,
:member:`ngtcp2_callbacks.remove_connection_id` is called.  Inside the
callback, remove the association for the Connection ID.

When a QUIC connection is closed, all associations for the connection
should be removed.  Remove all associations for Connection ID returned
from `ngtcp2_conn_get_scid2()`.  Association for the initial
Connection ID which can be obtained by calling
`ngtcp2_conn_get_client_initial_dcid2()` should also be removed.

Dealing with 0-RTT (early) data
-------------------------------

Client application has to remember the subset of the QUIC transport
parameters received from a server in the previous connection.
`ngtcp2_conn_encode_0rtt_transport_params2` returns the encoded QUIC
transport parameters that include these values.  When sending 0-RTT
data, the remembered transport parameters should be set via
`ngtcp2_conn_decode_and_set_0rtt_transport_params`.  Then client can
open streams with `ngtcp2_conn_open_bidi_streams` or
`ngtcp2_conn_open_uni_stream`.  Note that
`ngtcp2_conn_decode_and_set_0rtt_transport_params` does not invoke
neither :member:`ngtcp2_callbacks.extend_max_local_streams_bidi` nor
:member:`ngtcp2_callbacks.extend_max_local_streams_uni`.

Other than that, there is no difference between 0-RTT and 1-RTT data
in terms of API usage.

If early data is rejected by a server during TLS handshake, client
must call `ngtcp2_conn_tls_early_data_rejected`.  All connection
states altered during 0-RTT transmission are undone.  The library does
not retransmit 0-RTT data to server as 1-RTT data.  If an application
wishes to resend data, it has to reopen streams and writes data again.
See `ngtcp2_conn_tls_early_data_rejected`.

Closing streams
---------------

The send-side stream is closed when you call
`ngtcp2_conn_submit_stream_buf()` with
:macro:`NGTCP2_WRITE_STREAM_FLAG_FIN` flag set, and all data are
acknowledged.  The receive-side stream is closed when a local endpoint
receives fin from a remote endpoint, and all data are received.  And then
:member:`ngtcp2_callbacks.stream_close` is invoked.

Application can close stream abruptly by calling
`ngtcp2_conn_shutdown_stream`.  It has
`ngtcp2_conn_shutdown_stream_write` and
`ngtcp2_conn_shutdown_stream_read` variants that close the individual
side of a stream.

Stream data ownership
---------------------

Stream data is written into zngtcp2-issued ``TX_STREAM`` buffers.
Submitting accepted bytes transfers custody to the library.  The
application must not modify submitted bytes, and it does not need to
keep its own copy alive for retransmission.  The library releases the
retained payload after ACK accounting, retransmission cleanup, stream
teardown, connection close, or connection deletion.

Timers
------

The library does not ask an operating system for any timestamp.
Instead, an application has to supply timestamp to the library.  The
type of timestamp in ngtcp2 library is :type:`ngtcp2_tstamp` which is
nanosecond resolution.  The library only cares the difference of
timestamp, so it does not have to be a system clock.  A monotonic
clock should work better.  It should be same clock passed to
:member:`ngtcp2_settings.initial_ts`.  The duration in ngtcp2 library
is :type:`ngtcp2_duration` which is also nanosecond resolution.

`ngtcp2_conn_get_expiry2()` tells an application when timer fires.
When it fires, call `ngtcp2_conn_handle_expiry()`.  If it returns
:macro:`NGTCP2_ERR_IDLE_CLOSE`, it means that an idle timer has fired
for this particular connection.  In this case, drop the connection.
If it returns any of the other negative error codes, close the
connection and drain pending packet handoffs.  Otherwise, submit
application payload buffers as needed and pull packet handoffs.  An
application may call any number of additional `ngtcp2_conn_read_pkt()`
and `ngtcp2_conn_handle_expiry()` before pulling packets.  After
sending packets, new expiry is set.  The application should call
`ngtcp2_conn_get_expiry2()` to get a new deadline and set the timer.

Please note that :type:`ngtcp2_tstamp` of value ``UINT64_MAX`` is
treated as an invalid timestamp.  Do not pass ``UINT64_MAX`` to any
ngtcp2 functions which take :type:`ngtcp2_tstamp` unless it is
explicitly allowed.

Connection migration
--------------------

In QUIC, client application can migrate to a new local address.
`ngtcp2_conn_initiate_immediate_migration()` migrates to a new local
address without checking reachability.  On the other hand,
`ngtcp2_conn_initiate_migration()` migrates to a new local address
after a new path is validated (thus reachability is established).

Closing connection abruptly
---------------------------

In order to close QUIC connection abruptly, set the connection close
error state and drain the protected packet handoff produced by the
connection close path.  After the terminal packet is produced, the
connection enters the closing state.

The closing and draining state
------------------------------

After the terminal close packet is produced, the connection enters the
closing state.  When `ngtcp2_conn_read_pkt()` returns
:macro:`NGTCP2_ERR_DRAINING`, the connection has entered the draining
state.  In these states, application payload submission and
`ngtcp2_conn_read_pkt()` return an error (either
:macro:`NGTCP2_ERR_CLOSING` or :macro:`NGTCP2_ERR_DRAINING` depending
on the state).  If an application needs to send a packet containing
CONNECTION_CLOSE frame in the closing state, resend the retained
terminal handoff.  Therefore, after a connection has entered one of
these states, the application can discard :type:`ngtcp2_conn` object.
The closing and draining state should persist at least 3 times the
current PTO.

Error handling in general
-------------------------

In general, when error is returned from the ngtcp2 library function,
close the connection and drain the terminal packet handoff if one is
produced.  After a negative error code, calling `ngtcp2_conn_read_pkt`
or submitting new application payload is undefined except for the
errors that are defined as transitional.  See below and their
documentation.

If :macro:`NGTCP2_ERR_DROP_CONN` is returned from
`ngtcp2_conn_read_pkt`, a connection should be dropped without calling
the close packet path.  Similarly, if :macro:`NGTCP2_ERR_IDLE_CLOSE`
is returned from `ngtcp2_conn_handle_expiry`, a connection should be
dropped without the close packet path.  If
:macro:`NGTCP2_ERR_DRAINING` is returned from `ngtcp2_conn_read_pkt`,
a connection has entered the draining state, and no further packet
transmission is allowed.

The following error codes must be considered as transitional, and
application should keep connection alive:

* :macro:`NGTCP2_ERR_STREAM_DATA_BLOCKED`
* :macro:`NGTCP2_ERR_STREAM_SHUT_WR`
* :macro:`NGTCP2_ERR_STREAM_NOT_FOUND`
* :macro:`NGTCP2_ERR_STREAM_ID_BLOCKED`

Version negotiation
-------------------

Version negotiation is configured with the following
:type:`ngtcp2_settings` fields:

* :member:`ngtcp2_settings.preferred_versions` and
  :member:`ngtcp2_settings.preferred_versionslen`
* :member:`ngtcp2_settings.available_versions` and
  :member:`ngtcp2_settings.available_versionslen`
* :member:`ngtcp2_settings.original_version`

*client_chosen_version* passed to `ngtcp2_conn_client_new` also
influence the version negotiation process.

By default, client sends *client_chosen_version* passed to
`ngtcp2_conn_client_new` in available_versions field of
version_information QUIC transport parameter.  That means there is no
chance for server to select the other compatible version.  Meanwhile,
ngtcp2 supports QUIC v2 version (:macro:`NGTCP2_PROTO_VER_V2`).
Including both :macro:`NGTCP2_PROTO_VER_V1` and
:macro:`NGTCP2_PROTO_VER_V2` in
:member:`ngtcp2_settings.available_versions` field allows server to
choose :macro:`NGTCP2_PROTO_VER_V2` which is compatible to
:macro:`NGTCP2_PROTO_VER_V1`.

By default, server sends :macro:`NGTCP2_PROTO_VER_V1` in
available_versions field of version_information QUIC transport
parameter.  Because there is no particular preferred versions
specified, server will accept any supported version.  In order to set
the version preference, specify
:member:`ngtcp2_settings.preferred_versions` field.  If it is
specified, server sends them in available_versions field of
version_information QUIC transport parameter unless
:member:`ngtcp2_settings.available_versionslen` is not zero.
Specifying :member:`ngtcp2_settings.available_versions` overrides the
above mentioned default behavior.  Even if there is no overlap between
:member:`ngtcp2_settings.preferred_versions` and available_versions
field plus *client_chosen_version* from client, as long as
*client_chosen_version* is supported by server, server accepts
*client_chosen_version*.

If client receives Version Negotiation packet from server,
`ngtcp2_conn_read_pkt` returns
:macro:`NGTCP2_ERR_RECV_VERSION_NEGOTIATION`.
:member:`ngtcp2_callbacks.recv_version_negotiation` is also invoked if
set.  It will provide the versions contained in the packet.  Client
then either gives up the connection attempt, or selects the version
from Version Negotiation packet, and starts new connection attempt
with that version.  In the latter case, the initial version that used
in the first connection attempt must be set to
:member:`ngtcp2_settings.original_version`.  The client version
preference that is used when selecting a version from Version
Negotiation packet must be set to
:member:`ngtcp2_settings.preferred_versions`.
:member:`ngtcp2_settings.available_versions` must include the selected
version.  The selected version becomes *client_chosen_version* in the
second connection attempt, and must be passed to
`ngtcp2_conn_client_new`.

Server never know whether client reacted upon Version Negotiation
packet or not, and there is no particular setup for server to make
this incompatible version negotiation work.

Thread safety
-------------

ngtcp2 library is thread-safe as long as a single :type:`ngtcp2_conn`
object is accessed by a single thread at a time.  For multi-threaded
applications, it is recommended to create :type:`ngtcp2_conn` objects
per thread to avoid locks.

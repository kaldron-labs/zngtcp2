ngtcp2
======

"Call it TCP/2.  One More Time."

ngtcp2 project is an effort to implement `RFC9000
<https://datatracker.ietf.org/doc/html/rfc9000>`_ QUIC protocol.

Documentation
-------------

`Online documentation <https://nghttp2.org/zngtcp2/>`_ is available.

Public test server
------------------

The following endpoints are available to try out ngtcp2
implementation:

- https://nghttp2.org:4433
- https://nghttp2.org:4434 (requires address validation token)
- https://nghttp2.org (powered by `nghttpx
  <https://nghttp2.org/documentation/nghttpx.1.html>`_)

  This endpoints sends Alt-Svc header field to clients if it is
  accessed via HTTP/1.1 or HTTP/2 to tell them that HTTP/3 is
  available at UDP 443.

Requirements
------------

The libzngtcp2 C library itself does not depend on any external
libraries.  The example client, and server are written in C++23, and
should compile with the modern C++ compilers (e.g., clang >= 19, or
gcc >= 15).

The following packages are required to configure the build system:

- pkg-config >= 0.20
- autoconf
- automake
- autotools-dev
- libtool

To build sources under the examples directory, libev and nghttp3 are
required:

- libev
- `nghttp3 <https://github.com/zngtcp2/nghttp3>`_ for HTTP/3

The crypto helper library and examples require zpicotls.  zpicotls uses
OpenSSL-backed crypto primitives, so OpenSSL >= 1.1.1 is also required.

Before building from git
------------------------

When build from git, run the following command to pull submodules:

.. code-block:: shell

   $ git submodule update --init

Build with zpicotls
-------------------

.. code-block:: shell

   $ git clone --recursive https://github.com/zngtcp2/zpicotls
   $ cd zpicotls
   $ cmake -B build
   $ cmake --build build -j$(nproc)
   $ cd ..
   $ git clone --recursive https://github.com/zngtcp2/nghttp3
   $ cd nghttp3
   $ autoreconf -i
   $ ./configure --prefix=$PWD/build --enable-lib-only
   $ make -j$(nproc) check
   $ make install
   $ cd ..
   $ git clone --recursive  https://github.com/zngtcp2/ngtcp2
   $ cd ngtcp2
   $ autoreconf -i
   $ # For Mac users who have installed libev with MacPorts, append
   $ # LIBEV_CFLAGS="-I/opt/homebrew/Cellar/libev/4.33/include" LIBEV_LIBS="-L/opt/homebrew/Cellar/libev/4.33/lib -lev"
   $ ./configure PKG_CONFIG_PATH=$PWD/../nghttp3/build/lib/pkgconfig \
       ZPICOTLS_CFLAGS="-I$PWD/../zpicotls/include" \
       ZPICOTLS_LIBS="-L$PWD/../zpicotls/build -lzpicotls-openssl -lzpicotls-core"
   $ make -j$(nproc) check

Client/Server
-------------

After successful build, the client and server executable should be
found under examples directory.  They talk HTTP/3.

Client
~~~~~~

.. code-block:: shell

   $ examples/ptlsclient [OPTIONS] <HOST> <PORT> [<URI>...]

The notable options are:

- ``-d``, ``--data=<PATH>``: Read data from <PATH> and send it to a
  peer.

Server
~~~~~~

.. code-block:: shell

   $ examples/ptlsserver [OPTIONS] <ADDR> <PORT> <PRIVATE_KEY_FILE> <CERTIFICATE_FILE>

The notable options are:

- ``-V``, ``--validate-addr``: Enforce stateless address validation.

Resumption and 0-RTT
--------------------

In order to resume a session, a session ticket, and a transport
parameters must be fetched from server.  First, run
examples/ptlsclient with --session-file, and --tp-file options which
specify a path to session ticket, and transport parameter files
respectively to save them locally.

Once these files are available, run examples/ptlsclient with the same
arguments again.  You will see that session is resumed in your log if
resumption succeeds.  Resuming session makes server's first Handshake
packet pretty small because it does not send its certificates.

To send 0-RTT data, after making sure that resumption works, use -d
option to specify a file which contains data to send.

Token (Not something included in Retry packet)
----------------------------------------------

QUIC server might send a token to client after connection has been
established.  Client can send this token in subsequent connection to
the server.  Server verifies the token and if it succeeds, the address
validation completes and lifts some restrictions on server which might
speed up transfer.  In order to save and/or load a token,
use --token-file option of examples/ptlsclient.  The given file is
overwritten if it already exists when storing a token.

Crypto helper library
---------------------

In order to make TLS stack integration less painful, zngtcp2 provides
one supported crypto helper library:

- libzngtcp2_crypto_zpicotls: Use zpicotls as TLS backend.

The installed helper headers live under ``include/zngtcp2``.  The
zpicotls provider installs mandatory packet crypto operations used by
the buffer-oriented packet APIs.

QUIC protocol extensions
-------------------------

The library implements the following QUIC protocol extensions:

- `An Unreliable Datagram Extension to QUIC
  <https://datatracker.ietf.org/doc/html/rfc9221>`_
- `Greasing the QUIC Bit
  <https://datatracker.ietf.org/doc/html/rfc9287>`_
- `Compatible Version Negotiation for QUIC
  <https://datatracker.ietf.org/doc/html/rfc9368>`_
- `QUIC Version 2
  <https://datatracker.ietf.org/doc/html/rfc9369>`_

Configuring Wireshark for QUIC
------------------------------

`Wireshark <https://www.wireshark.org/download.html>`_ can be configured to
analyze QUIC traffic using the following steps:

1. Set *SSLKEYLOGFILE* environment variable:

   .. code-block:: shell

      $ export SSLKEYLOGFILE=quic_keylog_file

2. Set the port that QUIC uses

   Go to *Preferences->Protocols->QUIC* and set the port the program
   listens to.  In the case of the example application this would be
   the port specified on the command line.

3. Set Pre-Master-Secret logfile

   Go to *Preferences->Protocols->TLS* and set the *Pre-Master-Secret
   log file* to the same value that was specified for *SSLKEYLOGFILE*.

4. Choose the correct network interface for capturing

   Make sure you choose the correct network interface for
   capturing. For example, if using localhost choose the *loopback*
   network interface on macos.

5. Create a filter

   Create A filter for the udp.port and set the port to the port the
   application is listening to. For example:

   .. code-block:: text

      udp.port == 7777

License
-------

The MIT License

Copyright (c) 2016 ngtcp2 contributors

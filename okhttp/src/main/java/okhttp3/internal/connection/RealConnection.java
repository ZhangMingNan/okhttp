/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package okhttp3.internal.connection;

import java.io.IOException;
import java.lang.ref.Reference;
import java.net.ConnectException;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownServiceException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nullable;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import okhttp3.Address;
import okhttp3.Call;
import okhttp3.Connection;
import okhttp3.ConnectionPool;
import okhttp3.ConnectionSpec;
import okhttp3.EventListener;
import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;
import okhttp3.internal.Internal;
import okhttp3.internal.Util;

import okhttp3.internal.http.HttpCodec;
import okhttp3.internal.http.HttpHeaders;
import okhttp3.internal.http1.Http1Codec;

import okhttp3.internal.platform.Platform;


import okio.BufferedSink;
import okio.BufferedSource;
import okio.Okio;
import okio.Source;

import static java.net.HttpURLConnection.HTTP_OK;
import static java.net.HttpURLConnection.HTTP_PROXY_AUTH;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static okhttp3.internal.Util.closeQuietly;

public final class RealConnection implements Connection {
    private static final String NPE_THROW_WITH_NULL = "throw with null exception";
    private static final int MAX_TUNNEL_ATTEMPTS = 21;

    private final ConnectionPool connectionPool;
    private final Route route;

    // The fields below are initialized by connect() and never reassigned.

    /**
     * The low-level TCP socket.
     */
    private Socket rawSocket;

    /**
     * The application layer socket. Either an {@link SSLSocket} layered over {@link #rawSocket}, or
     * {@link #rawSocket} itself if this connection does not use SSL.
     */
    private Socket socket;

    private Protocol protocol;
    private BufferedSource source;
    private BufferedSink sink;

    // The fields below track connection state and are guarded by connectionPool.

    /**
     * If true, no new streams can be created on this connection. Once true this is always true.
     */
    public boolean noNewStreams;

    public int successCount;

    /**
     * The maximum number of concurrent streams that can be carried by this connection. If {@code
     * allocations.size() < allocationLimit} then new streams can be created on this connection.
     */
    public int allocationLimit = 1;

    /**
     * Current streams carried by this connection.
     */
    public final List<Reference<StreamAllocation>> allocations = new ArrayList<>();

    /**
     * Nanotime timestamp when {@code allocations.size()} reached zero.
     */
    public long idleAtNanos = Long.MAX_VALUE;

    public RealConnection(ConnectionPool connectionPool, Route route) {
        this.connectionPool = connectionPool;
        this.route = route;
    }

    public static RealConnection testConnection(
            ConnectionPool connectionPool, Route route, Socket socket, long idleAtNanos) {
        RealConnection result = new RealConnection(connectionPool, route);
        result.socket = socket;
        result.idleAtNanos = idleAtNanos;
        return result;
    }

    public void connect(int connectTimeout, int readTimeout, int writeTimeout,
                        boolean connectionRetryEnabled, Call call, EventListener eventListener) {
        if (protocol != null) throw new IllegalStateException("already connected");

        RouteException routeException = null;
        List<ConnectionSpec> connectionSpecs = route.address().connectionSpecs();
        ConnectionSpecSelector connectionSpecSelector = new ConnectionSpecSelector(connectionSpecs);

        if (route.address().sslSocketFactory() == null) {
            if (!connectionSpecs.contains(ConnectionSpec.CLEARTEXT)) {
                throw new RouteException(new UnknownServiceException(
                        "CLEARTEXT communication not enabled for client"));
            }
            String host = route.address().url().host();
            if (!Platform.get().isCleartextTrafficPermitted(host)) {
                throw new RouteException(new UnknownServiceException(
                        "CLEARTEXT communication to " + host + " not permitted by network security policy"));
            }
        }

        while (true) {
            try {
                if (route.requiresTunnel()) {
                    connectTunnel(connectTimeout, readTimeout, writeTimeout, call, eventListener);
                    if (rawSocket == null) {
                        // We were unable to connect the tunnel but properly closed down our resources.
                        break;
                    }
                } else {
                    connectSocket(connectTimeout, readTimeout, call, eventListener);
                }
                establishProtocol(connectionSpecSelector, call, eventListener);
                eventListener.connectEnd(call, route.socketAddress(), route.proxy(), protocol);
                break;
            } catch (IOException e) {
                closeQuietly(socket);
                closeQuietly(rawSocket);
                socket = null;
                rawSocket = null;
                source = null;
                sink = null;
                protocol = null;

                eventListener.connectFailed(call, route.socketAddress(), route.proxy(), null, e);

                if (routeException == null) {
                    routeException = new RouteException(e);
                } else {
                    routeException.addConnectException(e);
                }

                if (!connectionRetryEnabled || !connectionSpecSelector.connectionFailed(e)) {
                    throw routeException;
                }
            }
        }

        if (route.requiresTunnel() && rawSocket == null) {
            ProtocolException exception = new ProtocolException("Too many tunnel connections attempted: "
                    + MAX_TUNNEL_ATTEMPTS);
            throw new RouteException(exception);
        }

    }

    /**
     * Does all the work to build an HTTPS connection over a proxy tunnel. The catch here is that a
     * proxy server can issue an auth challenge and then close the connection.
     */
    private void connectTunnel(int connectTimeout, int readTimeout, int writeTimeout, Call call,
                               EventListener eventListener) throws IOException {
        Request tunnelRequest = createTunnelRequest();
        HttpUrl url = tunnelRequest.url();
        for (int i = 0; i < MAX_TUNNEL_ATTEMPTS; i++) {
            connectSocket(connectTimeout, readTimeout, call, eventListener);
            tunnelRequest = createTunnel(readTimeout, writeTimeout, tunnelRequest, url);

            if (tunnelRequest == null) break; // Tunnel successfully created.

            // The proxy decided to close the connection after an auth challenge. We need to create a new
            // connection, but this time with the auth credentials.
            closeQuietly(rawSocket);
            rawSocket = null;
            sink = null;
            source = null;
            eventListener.connectEnd(call, route.socketAddress(), route.proxy(), null);
        }
    }

    /**
     * Does all the work necessary to build a full HTTP or HTTPS connection on a raw socket.
     */
    private void connectSocket(int connectTimeout, int readTimeout, Call call,
                               EventListener eventListener) throws IOException {
        Proxy proxy = route.proxy();
        Address address = route.address();

        rawSocket = proxy.type() == Proxy.Type.DIRECT || proxy.type() == Proxy.Type.HTTP
                ? address.socketFactory().createSocket()
                : new Socket(proxy);

        eventListener.connectStart(call, route.socketAddress(), proxy);
        rawSocket.setSoTimeout(readTimeout);
        try {
            Platform.get().connectSocket(rawSocket, route.socketAddress(), connectTimeout);
        } catch (ConnectException e) {
            ConnectException ce = new ConnectException("Failed to connect to " + route.socketAddress());
            ce.initCause(e);
            throw ce;
        }

        // The following try/catch block is a pseudo hacky way to get around a crash on Android 7.0
        // More details:
        // https://github.com/square/okhttp/issues/3245
        // https://android-review.googlesource.com/#/c/271775/
        try {
            source = Okio.buffer(Okio.source(rawSocket));
            sink = Okio.buffer(Okio.sink(rawSocket));
        } catch (NullPointerException npe) {
            if (NPE_THROW_WITH_NULL.equals(npe.getMessage())) {
                throw new IOException(npe);
            }
        }
    }

    private void establishProtocol(ConnectionSpecSelector connectionSpecSelector, Call call,
                                   EventListener eventListener) throws IOException {
        if (route.address().sslSocketFactory() == null) {
            protocol = Protocol.HTTP_1_1;
            socket = rawSocket;
            return;
        }

        eventListener.secureConnectStart(call);
        connectTls(connectionSpecSelector);


    }

    private void connectTls(ConnectionSpecSelector connectionSpecSelector) throws IOException {
        Address address = route.address();
        SSLSocketFactory sslSocketFactory = address.sslSocketFactory();
        boolean success = false;
        SSLSocket sslSocket = null;
        try {
            // Create the wrapper over the connected socket.
            sslSocket = (SSLSocket) sslSocketFactory.createSocket(
                    rawSocket, address.url().host(), address.url().port(), true /* autoClose */);

            // Configure the socket's ciphers, TLS versions, and extensions.
            ConnectionSpec connectionSpec = connectionSpecSelector.configureSecureSocket(sslSocket);
            if (connectionSpec.supportsTlsExtensions()) {
                Platform.get().configureTlsExtensions(
                        sslSocket, address.url().host(), address.protocols());
            }

            // Force handshake. This can throw!
            sslSocket.startHandshake();


            // Success! Save the handshake and the ALPN protocol.
            String maybeProtocol = connectionSpec.supportsTlsExtensions()
                    ? Platform.get().getSelectedProtocol(sslSocket)
                    : null;
            socket = sslSocket;
            source = Okio.buffer(Okio.source(socket));
            sink = Okio.buffer(Okio.sink(socket));

            protocol = maybeProtocol != null
                    ? Protocol.get(maybeProtocol)
                    : Protocol.HTTP_1_1;
            success = true;
        } catch (AssertionError e) {
            if (Util.isAndroidGetsocknameError(e)) throw new IOException(e);
            throw e;
        } finally {
            if (sslSocket != null) {
                Platform.get().afterHandshake(sslSocket);
            }
            if (!success) {
                closeQuietly(sslSocket);
            }
        }
    }

    /**
     * To make an HTTPS connection over an HTTP proxy, send an unencrypted CONNECT request to create
     * the proxy connection. This may need to be retried if the proxy requires authorization.
     */
    private Request createTunnel(int readTimeout, int writeTimeout, Request tunnelRequest,
                                 HttpUrl url) throws IOException {
        // Make an SSL Tunnel on the first message pair of each SSL + proxy connection.
        String requestLine = "CONNECT " + Util.hostHeader(url, true) + " HTTP/1.1";
        while (true) {
            Http1Codec tunnelConnection = new Http1Codec(null, null, source, sink);
            source.timeout().timeout(readTimeout, MILLISECONDS);
            sink.timeout().timeout(writeTimeout, MILLISECONDS);
            tunnelConnection.writeRequest(tunnelRequest.headers(), requestLine);
            tunnelConnection.finishRequest();
            Response response = tunnelConnection.readResponseHeaders(false)
                    .request(tunnelRequest)
                    .build();
            // The response body from a CONNECT should be empty, but if it is not then we should consume
            // it before proceeding.
            long contentLength = HttpHeaders.contentLength(response);
            if (contentLength == -1L) {
                contentLength = 0L;
            }
            Source body = tunnelConnection.newFixedLengthSource(contentLength);
            Util.skipAll(body, Integer.MAX_VALUE, TimeUnit.MILLISECONDS);
            body.close();

            switch (response.code()) {
                case HTTP_OK:
                    // Assume the server won't send a TLS ServerHello until we send a TLS ClientHello. If
                    // that happens, then we will have buffered bytes that are needed by the SSLSocket!
                    // This check is imperfect: it doesn't tell us whether a handshake will succeed, just
                    // that it will almost certainly fail because the proxy has sent unexpected data.
                    if (!source.buffer().exhausted() || !sink.buffer().exhausted()) {
                        throw new IOException("TLS tunnel buffered too many bytes!");
                    }
                    return null;

                default:
                    throw new IOException(
                            "Unexpected response code for CONNECT: " + response.code());
            }
        }
    }

    /**
     * Returns a request that creates a TLS tunnel via an HTTP proxy. Everything in the tunnel request
     * is sent unencrypted to the proxy server, so tunnels include only the minimum set of headers.
     * This avoids sending potentially sensitive data like HTTP cookies to the proxy unencrypted.
     */
    private Request createTunnelRequest() {
        return new Request.Builder()
                .url(route.address().url())
                .header("Host", Util.hostHeader(route.address().url(), true))
                .header("Proxy-Connection", "Keep-Alive") // For HTTP/1.0 proxies like Squid.
                .header("User-Agent", Version.userAgent())
                .build();
    }

    /**
     * Returns true if this connection can carry a stream allocation to {@code address}. If non-null
     * {@code route} is the resolved route for a connection.
     */
    public boolean isEligible(Address address, @Nullable Route route) {
        // If this connection is not accepting new streams, we're done.
        if (allocations.size() >= allocationLimit || noNewStreams) return false;

        // If the non-host fields of the address don't overlap, we're done.
        if (!Internal.instance.equalsNonHost(this.route.address(), address)) return false;

        // If the host exactly matches, we're done: this connection can carry the address.
        if (address.url().host().equals(this.route().address().url().host())) {
            return true; // This connection is a perfect match.
        }
        if (route == null) return false;
        if (route.proxy().type() != Proxy.Type.DIRECT) return false;
        if (this.route.proxy().type() != Proxy.Type.DIRECT) return false;
        if (!this.route.socketAddress().equals(route.socketAddress())) return false;

        if (!supportsUrl(address.url())) return false;
        return true; // The caller's address can be carried by this connection.
    }

    public boolean supportsUrl(HttpUrl url) {
        if (url.port() != route.address().url().port()) {
            return false; // Port mismatch.
        }

        return true; // Success. The URL is supported.
    }

    public HttpCodec newCodec(OkHttpClient client, Interceptor.Chain chain,
                              StreamAllocation streamAllocation) throws SocketException {
            socket.setSoTimeout(chain.readTimeoutMillis());
            source.timeout().timeout(chain.readTimeoutMillis(), MILLISECONDS);
            sink.timeout().timeout(chain.writeTimeoutMillis(), MILLISECONDS);
            return new Http1Codec(client, streamAllocation, source, sink);
    }

    @Override
    public Route route() {
        return route;
    }

    public void cancel() {
        // Close the raw socket so we don't end up doing synchronous I/O.
        closeQuietly(rawSocket);
    }

    @Override
    public Socket socket() {
        return socket;
    }

    /**
     * Returns true if this connection is ready to host new streams.
     */
    public boolean isHealthy(boolean doExtensiveChecks) {
        if (socket.isClosed() || socket.isInputShutdown() || socket.isOutputShutdown()) {
            return false;
        }

        if (doExtensiveChecks) {
            try {
                int readTimeout = socket.getSoTimeout();
                try {
                    socket.setSoTimeout(1);
                    if (source.exhausted()) {
                        return false; // Stream is exhausted; socket is closed.
                    }
                    return true;
                } finally {
                    socket.setSoTimeout(readTimeout);
                }
            } catch (SocketTimeoutException ignored) {
                // Read timed out; socket is good.
            } catch (IOException e) {
                return false; // Couldn't read; socket is closed.
            }
        }

        return true;
    }






    @Override
    public Protocol protocol() {
        return protocol;
    }

    @Override
    public String toString() {
        return "Connection{"
                + route.address().url().host() + ":" + route.address().url().port()
                + ", proxy="
                + route.proxy()
                + " hostAddress="
                + route.socketAddress()
                + " protocol="
                + protocol
                + '}';
    }
}

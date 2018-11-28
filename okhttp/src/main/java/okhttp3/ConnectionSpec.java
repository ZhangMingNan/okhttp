/*
 * Copyright (C) 2014 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package okhttp3;

import javax.annotation.Nullable;
import javax.net.ssl.SSLSocket;
import java.util.List;

import static okhttp3.internal.Util.*;

/**
 * Specifies configuration for the socket connection that HTTP traffic travels through. For {@code
 * https:} URLs, this includes the TLS version and cipher suites to use when negotiating a secure
 * connection.
 *
 * <p>The TLS versions configured in a connection spec are only be used if they are also enabled in
 * the SSL socket. For example, if an SSL socket does not have TLS 1.3 enabled, it will not be used
 * even if it is present on the connection spec. The same policy also applies to cipher suites.
 *
 * <p>Use {@link Builder#allEnabledTlsVersions()} and {@link Builder#allEnabledCipherSuites} to
 * defer all feature selection to the underlying SSL socket.
 */
public final class ConnectionSpec {

  // This is nearly equal to the cipher suites supported in Chrome 51, current as of 2016-05-25.
  // All of these suites are available on Android 7.0; earlier releases support a subset of these
  // suites. https://github.com/square/okhttp/issues/1972
  private static final CipherSuite[] APPROVED_CIPHER_SUITES = new CipherSuite[] {
      CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

      // Note that the following cipher suites are all on HTTP/2's bad cipher suites list. We'll
      // continue to include them until better suites are commonly available. For example, none
      // of the better cipher suites listed above shipped with Android 4.4 or Java 7.
      CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
      CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
      CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
      CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
      CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
      CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
      CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
      CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
      CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
  };





  /** Unencrypted, unauthenticated connections for {@code http:} URLs. */
  public static final ConnectionSpec CLEARTEXT = new Builder(false).build();


  final boolean supportsTlsExtensions;
  final @Nullable String[] cipherSuites;


  ConnectionSpec(Builder builder) {

    this.cipherSuites = builder.cipherSuites;

    this.supportsTlsExtensions = builder.supportsTlsExtensions;
  }



  /**
   * Returns the cipher suites to use for a connection. Returns null if all of the SSL socket's
   * enabled cipher suites should be used.
   */
  public @Nullable List<CipherSuite> cipherSuites() {
    return cipherSuites != null ? CipherSuite.forJavaNames(cipherSuites) : null;
  }



  public boolean supportsTlsExtensions() {
    return supportsTlsExtensions;
  }

  /** Applies this spec to {@code sslSocket}. */
  void apply(SSLSocket sslSocket, boolean isFallback) {
    ConnectionSpec specToApply = supportedSpec(sslSocket, isFallback);

    if (specToApply.cipherSuites != null) {
      sslSocket.setEnabledCipherSuites(specToApply.cipherSuites);
    }
  }

  /**
   * Returns a copy of this that omits cipher suites and TLS versions not enabled by {@code
   * sslSocket}.
   */
  private ConnectionSpec supportedSpec(SSLSocket sslSocket, boolean isFallback) {
    String[] cipherSuitesIntersection = cipherSuites != null
        ? intersect(CipherSuite.ORDER_BY_NAME, sslSocket.getEnabledCipherSuites(), cipherSuites)
        : sslSocket.getEnabledCipherSuites();


    // In accordance with https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00
    // the SCSV cipher is added to signal that a protocol fallback has taken place.
    String[] supportedCipherSuites = sslSocket.getSupportedCipherSuites();
    int indexOfFallbackScsv = indexOf(
        CipherSuite.ORDER_BY_NAME, supportedCipherSuites, "TLS_FALLBACK_SCSV");
    if (isFallback && indexOfFallbackScsv != -1) {
      cipherSuitesIntersection = concat(
          cipherSuitesIntersection, supportedCipherSuites[indexOfFallbackScsv]);
    }

    return new Builder(this)
        .cipherSuites(cipherSuitesIntersection)
        .build();
  }


  public boolean isCompatible(SSLSocket socket) {




    if (cipherSuites != null && !nonEmptyIntersection(
        CipherSuite.ORDER_BY_NAME, cipherSuites, socket.getEnabledCipherSuites())) {
      return false;
    }

    return true;
  }

  @Override public boolean equals(@Nullable Object other) {
    if (!(other instanceof ConnectionSpec)) return false;
    if (other == this) return true;

    ConnectionSpec that = (ConnectionSpec) other;


    return true;
  }

  @Override public int hashCode() {
    int result = 17;

    return result;
  }

  @Override public String toString() {


    String cipherSuitesString = cipherSuites != null ? cipherSuites().toString() : "[all enabled]";

    return "ConnectionSpec("
        + "cipherSuites=" + cipherSuitesString

        + ", supportsTlsExtensions=" + supportsTlsExtensions
        + ")";
  }

  public static final class Builder {
    boolean tls;
    @Nullable String[] cipherSuites;
    @Nullable String[] tlsVersions;
    boolean supportsTlsExtensions;

    Builder(boolean tls) {
      this.tls = tls;
    }

    public Builder(ConnectionSpec connectionSpec) {

      this.cipherSuites = connectionSpec.cipherSuites;

      this.supportsTlsExtensions = connectionSpec.supportsTlsExtensions;
    }

    public Builder allEnabledCipherSuites() {
      if (!tls) throw new IllegalStateException("no cipher suites for cleartext connections");
      this.cipherSuites = null;
      return this;
    }

    public Builder cipherSuites(CipherSuite... cipherSuites) {
      if (!tls) throw new IllegalStateException("no cipher suites for cleartext connections");

      String[] strings = new String[cipherSuites.length];
      for (int i = 0; i < cipherSuites.length; i++) {
        strings[i] = cipherSuites[i].javaName;
      }
      return cipherSuites(strings);
    }

    public Builder cipherSuites(String... cipherSuites) {
      if (!tls) throw new IllegalStateException("no cipher suites for cleartext connections");

      if (cipherSuites.length == 0) {
        throw new IllegalArgumentException("At least one cipher suite is required");
      }

      this.cipherSuites = cipherSuites.clone(); // Defensive copy.
      return this;
    }

    public Builder allEnabledTlsVersions() {
      if (!tls) throw new IllegalStateException("no TLS versions for cleartext connections");
      this.tlsVersions = null;
      return this;
    }


    public Builder tlsVersions(String... tlsVersions) {
      if (!tls) throw new IllegalStateException("no TLS versions for cleartext connections");

      if (tlsVersions.length == 0) {
        throw new IllegalArgumentException("At least one TLS version is required");
      }

      this.tlsVersions = tlsVersions.clone(); // Defensive copy.
      return this;
    }

    public Builder supportsTlsExtensions(boolean supportsTlsExtensions) {
      if (!tls) throw new IllegalStateException("no TLS extensions for cleartext connections");
      this.supportsTlsExtensions = supportsTlsExtensions;
      return this;
    }

    public ConnectionSpec build() {
      return new ConnectionSpec(this);
    }
  }
}

/*
 * Copyright (C) 2015 Square, Inc.
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
package okhttp3.internal.connection;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ProtocolException;
import java.net.UnknownServiceException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSocket;

import okhttp3.internal.Internal;

/**
 * Handles the connection spec fallback strategy: When a secure socket connection fails due to a
 * handshake / protocol problem the connection may be retried with different protocols. Instances
 * are stateful and should be created and used for a single connection attempt.
 */
public final class ConnectionSpecSelector {


  private int nextModeIndex;
  private boolean isFallbackPossible;
  private boolean isFallback;





  public boolean connectionFailed(IOException e) {
    // Any future attempt to connect using this strategy will be a fallback attempt.
    isFallback = true;

    if (!isFallbackPossible) {
      return false;
    }

    // If there was a protocol problem, don't recover.
    if (e instanceof ProtocolException) {
      return false;
    }

    // If there was an interruption or timeout (SocketTimeoutException), don't recover.
    // For the socket connect timeout case we do not try the same host with a different
    // ConnectionSpec: we assume it is unreachable.
    if (e instanceof InterruptedIOException) {
      return false;
    }

    // Look for known client-side or negotiation errors that are unlikely to be fixed by trying
    // again with a different connection spec.
    if (e instanceof SSLHandshakeException) {
      // If the problem was a CertificateException from the X509TrustManager,
      // do not retry.
      if (e.getCause() instanceof CertificateException) {
        return false;
      }
    }
    if (e instanceof SSLPeerUnverifiedException) {
      // e.g. a certificate pinning error.
      return false;
    }

    // On Android, SSLProtocolExceptions can be caused by TLS_FALLBACK_SCSV failures, which means we
    // retry those when we probably should not.
    return (e instanceof SSLHandshakeException || e instanceof SSLProtocolException);
  }



}

package io.vpv.net.service;

import io.vpv.net.model.CipherConfig;
import io.vpv.net.model.CipherResponse;
import io.vpv.net.util.SSLUtils;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Created by vprasanna on 4/3/18.
 */
public class CipherServiceTestEngine {

    public SSLSocket createSSLSocket(InetSocketAddress address,
                                             String host,
                                             int port,
                                             int readTimeout,
                                             int connectTimeout,
                                             SSLSocketFactory sf)
            throws IOException {
        //
        // Note: SSLSocketFactory has several create() methods.
        // Those that take arguments all connect immediately
        // and have no options for specifying a connection timeout.
        //
        // So, we have to create a socket and connect it (with a
        // connection timeout), then have the SSLSocketFactory wrap
        // the already-connected socket.
        //
        Socket sock = new Socket();
        sock.setSoTimeout(readTimeout);
        sock.connect(address, connectTimeout);

        // Wrap plain socket in an SSL socket
        return (SSLSocket) sf.createSocket(sock, host, port, true);
    }

    public String[] getJVMSupportedCipherSuites(String protocol, SecureRandom rand)
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sc = SSLContext.getInstance(protocol);

        sc.init(null, null, rand);

        return sc.getSocketFactory().getSupportedCipherSuites();
    }

    static final char[] hexChars = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f'};

    public String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);

        for (byte b : bytes)
            sb.append(hexChars[(b >> 4) & 0x0f])
                    .append(hexChars[b & 0x0f]);

        return sb.toString();
    }

    public List<CipherResponse> invoke(final CipherConfig params, Executor executor) throws InterruptedException, ExecutionException {
        String[] sslEnabledProtocols = params.getSslEnabledProtocols();
        List<String> supportedProtocols = params.getSupportedProtocols();
        Set<String> cipherSuites = params.getCipherSuites();
        final SecureRandom rand = params.getRand();
        String[] sslCipherSuites = params.getSslCipherSuites();
        final KeyManager[] keyManagers = params.getKeyManagers();
        final TrustManager[] trustManagers = params.getTrustManagers();
        final boolean showHandshakeErrors = params.isShowHandshakeErrors();
        final boolean stop = params.isStop();
        final boolean showSSLErrors = params.isShowSSLErrors();
        final boolean showErrors = params.isShowErrors();
        final boolean hideRejects = params.isHideRejects();
        final String reportFormat = params.getReportFormat();
        final String errorReportFormat = params.getErrorReportFormat();

        List<CipherResponse> responses = new ArrayList();
        List<Callable<CipherResponse>> futureResponses = new ArrayList();
        for (int i = 0; i < sslEnabledProtocols.length && !params.isStop(); ++i) {
            final String protocol = sslEnabledProtocols[i];

            String[] supportedCipherSuites = null;

            try {
                supportedCipherSuites = getJVMSupportedCipherSuites(protocol, rand);
            } catch (NoSuchAlgorithmException nsae) {
                System.out.print(String.format(params.getReportFormat(), "-----", protocol, " Not supported by client"));
                supportedProtocols.remove(protocol);
                continue;
            } catch (Exception e) {
                e.printStackTrace();
                continue; // Skip this protocol
            }

            // Restrict cipher suites to those specified by sslCipherSuites
            cipherSuites.clear();
            cipherSuites.addAll(Arrays.asList(supportedCipherSuites));

            if (null != sslCipherSuites)
                cipherSuites.retainAll(Arrays.asList(sslCipherSuites));

            if (cipherSuites.isEmpty()) {
                System.err.println("No overlapping cipher suites found for protocol " + protocol);
                supportedProtocols.remove(protocol);
                continue; // Go to the next protocol
            }

            for (final String cipherSuite : cipherSuites) {
                final Callable<CipherResponse> cipherResponseCallable = new Callable<CipherResponse>() {
                    @Override
                    public CipherResponse call() {
                        return performCipherTest(params, rand, keyManagers,
                                trustManagers, showHandshakeErrors,
                                stop, showSSLErrors, showErrors,
                                hideRejects, reportFormat, errorReportFormat,
                                protocol, cipherSuite);
                    }
                };
                futureResponses.add(cipherResponseCallable);
            }
        }
        ExecutorService executorService =
                new ThreadPoolExecutor(5, 5, 0L, TimeUnit.MILLISECONDS,
                        new LinkedBlockingQueue<Runnable>());

        final List<Future<CipherResponse>> futures = executorService.invokeAll(futureResponses);

        for (Future<CipherResponse> future : futures) {
            responses.add(future.get());
        }
        return responses;
    }

    private CipherResponse performCipherTest(CipherConfig params, SecureRandom rand, KeyManager[] keyManagers, TrustManager[] trustManagers, boolean showHandshakeErrors, boolean stop, boolean showSSLErrors, boolean showErrors, boolean hideRejects, String reportFormat, String errorReportFormat, String protocol, String cipherSuite) {
                    String status;

                    SSLSocketFactory sf = null;
                    try {
                        sf = SSLUtils.getSSLSocketFactory(protocol,
                                new String[]{protocol},
                                new String[]{cipherSuite},
                                rand,
                                trustManagers,
                                keyManagers);
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);
                    } catch (KeyManagementException e) {
                        throw new RuntimeException(e);
                    }

                    SSLSocket socket = null;
                    String error = null;

                    try {
                        socket = createSSLSocket(params.getAddress(), params.getHost(), params.getPort(), params.getConnectTimeout(), params.getReadTimeout(), sf);

                        socket.startHandshake();



                        SSLSession sess = socket.getSession();
                        //                    Thread.currentThread().sleep(200);System.exit(0);
                        //                    System.err.println("NORMAL SESSION = " + sess);
                        //                    System.err.println("MAIN THREADNAME: " + Thread.currentThread().getName());
                        assert protocol.equals(sess.getProtocol());
                        assert cipherSuite.equals(sess.getCipherSuite());


                        status = "Accepted";
                    } catch (SSLHandshakeException she) {
                        Throwable cause = she.getCause();
                        if (null != cause && cause instanceof CertificateException) {
                            status = "Untrusted";
                            error = "Server certificate is not trusted. All other connections will fail similarly.";
                        } else
                            status = "Rejected";

                        if (showHandshakeErrors)
                            error = "SHE: " + she.getLocalizedMessage() + ", type=" + she.getClass().getName() + ", nested=" + she.getCause();
                    } catch (SSLException ssle) {
                        if (showSSLErrors)
                            error = "SE: " + ssle.getLocalizedMessage();

                        status = "Rejected";
                    } catch (SocketTimeoutException ste) {
                        if (showErrors)
                            error = "SocketException" + ste.getLocalizedMessage();

                        status = "Timeout";
                    } catch (SocketException se) {
                        if (showErrors)
                            error = se.getLocalizedMessage();

                        status = "Failed";
                    } catch (IOException ioe) {
                        if (showErrors)
                            error = ioe.getLocalizedMessage();

                        ioe.printStackTrace();
                        status = "Failed";
                    } catch (Exception e) {
                        if (showErrors)
                            error = e.getLocalizedMessage();

                        e.printStackTrace();
                        status = "Failed";
                    } finally {
                        if (null != socket) try {
                            socket.close();
                        } catch (IOException ioe) {
                            ioe.printStackTrace();
                        }
                    }


        return new CipherResponse(cipherSuite, status, protocol, error, stop);


    }
}

package com.drnushooz.postgresql.jdbc;

import org.postgresql.ssl.WrappedFactory;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.Optional;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Socket factory where specific versions can be specified based on
 * jdk.tls.client.protocols and jdk.tls.client.cipherSuites properties. Possible protocol versions can be found
 * <a href="https:docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#sslcontext-algorithms">here</a>
 * and possible cipher suites can be found
 * <a href="https:docs.oracle.com/en/java/javase/12/docs/specs/security/standard-names.html#jsse-cipher-suite-names">here</a>
 */
public class ConfigurableVersionSSLFactory extends WrappedFactory {
    Logger logger = Logger.getLogger(this.getClass().getCanonicalName());

    private final String[] enabledProtocols;
    private final String[] enabledCipherSuites;

    public ConfigurableVersionSSLFactory() {
        enabledProtocols = Stream
            .of(System.getProperty("jdk.tls.client.protocols", "TLSv1.2").split(","))
            .map(String::trim)
            .toArray(String[]::new);

        String[] defaultEnabledCipherSuites = {
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        };
        enabledCipherSuites = Stream
            .of(System.getProperty("jdk.tls.client.cipherSuites",
                String.join(",", defaultEnabledCipherSuites)).split(","))
            .map(String::trim)
            .toArray(String[]::new);

        StringBuilder logMessageBuf = new StringBuilder();
        logMessageBuf.append(String.format("Initializing TLS with following protocol(s): %s",
            Arrays.stream(enabledProtocols).collect(Collectors.toList())));
        if (enabledCipherSuites.length > 0) {
            logMessageBuf.append(String.format(" and following cipher suite(s): %s",
                Arrays.stream(enabledCipherSuites).collect(Collectors.toList())));
        }

        logger.info(logMessageBuf.toString());
        factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
    }

    @Override
    public Socket createSocket() throws IOException {
        return enableCiphersOnSocket(enableProtocolsOnSocket(super.createSocket()));
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return enableCiphersOnSocket(enableProtocolsOnSocket(super.createSocket(host, port)));
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return enableCiphersOnSocket(enableProtocolsOnSocket(super.createSocket(host, port)));
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return enableCiphersOnSocket(enableProtocolsOnSocket(super.createSocket(host, port, localHost, localPort)));
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return enableCiphersOnSocket(enableProtocolsOnSocket(super.createSocket(address, port, localAddress, localPort)));
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return enableCiphersOnSocket(enableProtocolsOnSocket(super.createSocket(socket, host, port, autoClose)));
    }

    @Override
    public Socket createSocket(Socket s, InputStream consumed, boolean autoClose) throws IOException {
        return enableCiphersOnSocket(enableProtocolsOnSocket(super.createSocket(s, consumed, autoClose)));
    }

    private Socket enableCiphersOnSocket(final Socket socket) {
        return Optional.of(socket).map(s -> {
            if (s instanceof SSLSocket && enabledCipherSuites.length > 0)
                ((SSLSocket) (s)).setEnabledCipherSuites(enabledCipherSuites);
            return s;
        }).orElse(socket);
    }

    private Socket enableProtocolsOnSocket(final Socket socket) {
        return Optional.of(socket).map(s -> {
            if (s instanceof SSLSocket) {
                ((SSLSocket) (s)).setEnabledProtocols(enabledProtocols);
            }
            return s;
        }).orElse(socket);
    }
}

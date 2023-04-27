package com.drnushooz.postgresql.jdbc;

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class ConfigurableVersionSSLFactoryTest {
    
    @Test
    void testEnabledProtocols() throws IOException {
        ServerSocket ss = new ServerSocket(0);
        System.setProperty("jdk.tls.client.enabledProtocols", "TLSv1.1,TLSv1.2");
        SSLSocketFactory factory = new ConfigurableVersionSSLFactory();
        String[] enabledProtocols;
        try(SSLSocket s = (SSLSocket) factory.createSocket(ss.getInetAddress().getHostAddress(), ss.getLocalPort())) {
            enabledProtocols = s.getEnabledProtocols();
            ss.close();
        }
        assertFalse(Arrays.asList(enabledProtocols).contains("TLSv1.3"));
    }

    @Test
    void testEnabledCiphers() throws IOException {
        ServerSocket ss = new ServerSocket(0);
        String[] enabledCipherSuites = {
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
        };
        System.setProperty("jdk.tls.client.cipherSuites", String.join(",",enabledCipherSuites));
        SSLSocketFactory factory = new ConfigurableVersionSSLFactory();
        String[] cipherSuitesFromSocket;
        try(SSLSocket s = (SSLSocket) factory.createSocket(ss.getInetAddress().getHostAddress(), ss.getLocalPort())) {
            cipherSuitesFromSocket = s.getEnabledCipherSuites();
            ss.close();
        }
        assertFalse(Arrays.asList(cipherSuitesFromSocket).contains("TLS_KRB5_WITH_IDEA_CBC_SHA"));
    }
}

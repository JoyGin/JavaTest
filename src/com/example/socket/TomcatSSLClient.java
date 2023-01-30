package com.example.socket;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;

public class TomcatSSLClient {

//    private static final String SSL_TYPE = "SSL";
    private static final String SSL_TYPE = "TLS";

    private static final String X509 = "SunX509";

    private static final String KS_TYPE = "JKS";

    private SSLSocket sslSocket;

    public TomcatSSLClient(String targetHost, int port) throws Exception {

        SSLContext sslContext = createSSLContext();

        SSLSocketFactory sslcntFactory = (SSLSocketFactory) sslContext.getSocketFactory();

        sslSocket = (SSLSocket) sslcntFactory.createSocket(targetHost, port);

        String[] supported = sslSocket.getSupportedCipherSuites();

        sslSocket.setEnabledCipherSuites(supported);

    }

    private SSLContext createSSLContext() throws Exception {

        String classPath = getClass().getResource("").getPath();
        String packagePath = getClass().getPackageName().replace(".", "/") + "/";
        String projectPath = classPath.replace(packagePath, "");

        // 客户端信任证书链
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(X509);

        String serverKeyStoreFile = projectPath + "/ca.p12";

        String svrPassphrase = "123456";

        char[] svrPassword = svrPassphrase.toCharArray();

        KeyStore serverKeyStore = KeyStore.getInstance("pkcs12");

        serverKeyStore.load(new FileInputStream(serverKeyStoreFile), svrPassword);

        tmf.init(serverKeyStore);

        // 客户端持有证书链
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(X509);

        String clientKeyStoreFile = projectPath + "/client.p12";

        String cntPassphrase = "123456";

        char[] cntPassword = cntPassphrase.toCharArray();

        KeyStore clientKeyStore = KeyStore.getInstance("pkcs12");

        clientKeyStore.load(new FileInputStream(clientKeyStoreFile), cntPassword);

        kmf.init(clientKeyStore, cntPassword);

        SSLContext sslContext = SSLContext.getInstance(SSL_TYPE);

        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
//        sslContext.init(null, tmf.getTrustManagers(), null);

        return sslContext;

    }

    public String sayToSvr(String sayMsg) throws IOException {

        BufferedReader ioReader = new BufferedReader(new InputStreamReader(

                sslSocket.getInputStream()));

        PrintWriter ioWriter = new PrintWriter(sslSocket.getOutputStream());

        ioWriter.println(sayMsg);

        ioWriter.flush();

        return ioReader.readLine();

    }

    public static void main(String[] args) throws Exception {

        TomcatSSLClient sslSocket = new TomcatSSLClient("127.0.0.1", 443);

        BufferedReader ioReader = new BufferedReader(new InputStreamReader(System.in));

        String sayMsg = "";

        String svrRespMsg = "";

        while ((sayMsg = ioReader.readLine()) != null) {

            svrRespMsg = sslSocket.sayToSvr(sayMsg);

            if (svrRespMsg != null && !svrRespMsg.trim().equals("")) {

                System.out.println("服务器通过SSL协议响应:" + svrRespMsg);

            }

        }

    }

}

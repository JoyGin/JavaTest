package com.example.socket;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;

public class TomcatSSLServer {

//    private static final String SSL_TYPE = "SSL";
    private static final String SSL_TYPE = "TLS";

    private static final String KS_TYPE = "JKS";

    private static final String X509 = "SunX509";

    private final static int PORT = 443;

    private static TomcatSSLServer sslServer;

    private SSLServerSocket svrSocket;

    public static TomcatSSLServer getInstance() throws Exception {

        if (sslServer == null) {

            sslServer = new TomcatSSLServer();

        }

        return sslServer;

    }

    private TomcatSSLServer() throws Exception {

        SSLContext sslContext = createSSLContext();

        SSLServerSocketFactory serverFactory = sslContext.getServerSocketFactory();

        svrSocket = (SSLServerSocket) serverFactory.createServerSocket(PORT);

//        svrSocket.setNeedClientAuth(true);
        svrSocket.setNeedClientAuth(false);

        String[] supported = svrSocket.getEnabledCipherSuites();

        svrSocket.setEnabledCipherSuites(supported);

    }

    private SSLContext createSSLContext() throws Exception {

        String classPath = getClass().getResource("").getPath();
        String packagePath = getClass().getPackageName().replace(".", "/") + "/";
        String projectPath = classPath.replace(packagePath, "");

        // 服务器持有证书链
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(X509);

        String serverKeyStoreFile = projectPath + "/server.p12";

        String svrPassphrase = "123456";

        char[] svrPassword = svrPassphrase.toCharArray();

//        KeyStore serverKeyStore = KeyStore.getInstance(KS_TYPE);
        KeyStore serverKeyStore = KeyStore.getInstance("pkcs12");
        KeyStore.getDefaultType();

        serverKeyStore.load(new FileInputStream(serverKeyStoreFile), svrPassword);

        kmf.init(serverKeyStore, svrPassword);

        // 服务器信任证书链
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(X509);

        String clientKeyStoreFile = projectPath + "/ca.p12";

        String cntPassphrase = "123456";

        char[] cntPassword = cntPassphrase.toCharArray();

//        KeyStore clientKeyStore = KeyStore.getInstance(KS_TYPE);
        KeyStore clientKeyStore = KeyStore.getInstance("pkcs12");

        clientKeyStore.load(new FileInputStream(clientKeyStoreFile), cntPassword);

        tmf.init(clientKeyStore);

        SSLContext sslContext = SSLContext.getInstance(SSL_TYPE);

        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return sslContext;

    }

    public void startService() {

        SSLSocket cntSocket = null;

        BufferedReader ioReader = null;

        PrintWriter ioWriter = null;

        String tmpMsg = null;

        while (true) {

            try {

                cntSocket = (SSLSocket) svrSocket.accept();

                ioReader = new BufferedReader(new InputStreamReader(cntSocket.getInputStream()));

                ioWriter = new PrintWriter(cntSocket.getOutputStream());

                while ((tmpMsg = ioReader.readLine()) != null) {

                    System.out.println("客户端通过SSL协议发送信息:" + tmpMsg);

                    tmpMsg = "欢迎通过SSL协议连接";

                    ioWriter.println(tmpMsg);

                    ioWriter.flush();

                }

            } catch (IOException e) {

                e.printStackTrace();

            } finally {

                try {

                    if (cntSocket != null) cntSocket.close();

                } catch (Exception ex) {
                    ex.printStackTrace();
                }

            }

        }

    }

    public static void main(String[] args) throws Exception {

        TomcatSSLServer.getInstance().startService();

    }

}

package com.example.jks;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class TestJks {

    private static final String PASSWORD = "123456";
    private static final String SERVER_FILE = "/jks/server.jks";
    private static final String CA_FILE = "/jks/ca.jks";
    private static final String CLIENT_FILE = "/jks/client.jks";
    private static final String BKS_CLIENT_PATH = "/bks/client.bks";
    private static final String BKS_SERVER_PATH = "/bks/server.bks";
    private static final String TAG = "TestCertificate";

    public static void main(String[] args) {
        testJks();
        testBKS();
    }

    public static void testJks() {
        System.out.println("=============== testJks ===============");
        String classPath = TestJks.class.getResource("").getPath();
        String packagePath = TestJks.class.getPackageName().replace(".", "/") + "/";
        String projectPath = classPath.replace(packagePath, "");

        String serverKeyStorePath = projectPath + SERVER_FILE;
        String caKeyStorePath = projectPath + CA_FILE;
        String clientKeyStorePath = projectPath + CLIENT_FILE;

        KeyStore serverKeyStore;
        KeyStore caKeyStore;
        KeyStore clientKeyStore;
        try {
            // 服务端keystore
            InputStream serverInputStream = new FileInputStream(serverKeyStorePath);
            serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            serverKeyStore.load(serverInputStream, PASSWORD.toCharArray());
            Certificate server = serverKeyStore.getCertificate("server");

            caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            InputStream caInputStream = new FileInputStream(caKeyStorePath);
            caKeyStore.load(caInputStream, PASSWORD.toCharArray());
            Certificate ca = caKeyStore.getCertificate("ca");

            // 客户端keystore
            clientKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            InputStream keyInputStream = new FileInputStream(clientKeyStorePath);
            clientKeyStore.load(keyInputStream, PASSWORD.toCharArray());
            Certificate client = clientKeyStore.getCertificate("client");

            server.verify(ca.getPublicKey());
            client.verify(client.getPublicKey());

            // 输出服务器私钥
            Key privateKey = serverKeyStore.getKey("server", PASSWORD.toCharArray());
            System.out.println("privateKey algorithm: " + privateKey.getAlgorithm()
                    + ", format: " + privateKey.getFormat() + ", encoded: "
                    + new String(Base64.getEncoder().encode(privateKey.getEncoded())));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void testBKS() {
        System.out.println("=============== testBKS ===============");

        Security.addProvider(new BouncyCastleProvider());

        String classPath = TestJks.class.getResource("").getPath();
        String packagePath = TestJks.class.getPackageName().replace(".", "/") + "/";
        String projectPath = classPath.replace(packagePath, "");

        String clientKeyStorePath = projectPath + BKS_CLIENT_PATH;
        String serverKeyStorePath = projectPath + BKS_SERVER_PATH;

        try {

            // 客户端keystore
            KeyStore clientKeyStore = KeyStore.getInstance("BKS");
            clientKeyStore.load(new FileInputStream(clientKeyStorePath), PASSWORD.toCharArray());
            X509Certificate caCert = (X509Certificate) clientKeyStore.getCertificate("ca");
            X509Certificate clientCert = (X509Certificate) clientKeyStore.getCertificate("client");

            System.out.println("caCert subjectDN: " + caCert.getSubjectDN());
            System.out.println("clientCert subjectDN: " + clientCert.getSubjectDN());

            // 服务端keystore
            KeyStore serverKeyStore = KeyStore.getInstance("BKS");
            serverKeyStore.load(new FileInputStream(serverKeyStorePath), PASSWORD.toCharArray());
            X509Certificate caCertServer = (X509Certificate) serverKeyStore.getCertificate("ca");
            X509Certificate serverCert = (X509Certificate) serverKeyStore.getCertificate("server");

            System.out.println("caCertServer subjectDN: " + caCertServer.getSubjectDN());
            System.out.println("serverCert subjectDN: " + serverCert.getSubjectDN());

            // 输出服务器私钥
            Key privateKey = serverKeyStore.getKey("server", PASSWORD.toCharArray());
            System.out.println("privateKey algorithm: " + privateKey.getAlgorithm()
                    + ", format: " + privateKey.getFormat() + ", encoded: "
                    + new String(Base64.getEncoder().encode(privateKey.getEncoded())));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void analyzePrivateKey(PrivateKey key) {

    }
}

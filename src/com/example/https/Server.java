package com.example.https;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.Executors;

/**
 * java实现简单服务器：<a href="https://cloud.tencent.com/developer/article/1735038">
 *
 */
public class Server {
    public static void main(String[] args) throws Exception {
        HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress("127.0.0.1", 8080), 0);

        //创建一个HttpContext，将路径为/myserver请求映射到MyHttpHandler处理器
        httpsServer.createContext("/myserver", new MyHttpHandler());

        HttpsConfigurator httpsConfigurator = new MyHttpsConfigurator(createSSLContext());


        httpsServer.setHttpsConfigurator(httpsConfigurator);

        //设置服务器的线程池对象
        httpsServer.setExecutor(Executors.newFixedThreadPool(10));

        //启动服务器
        httpsServer.start();
    }

    private static SSLContext createSSLContext() throws Exception {

        String classPath = Server.class.getResource("").getPath();
        String packagePath = Server.class.getPackageName().replace(".", "/") + "/";
        String projectPath = classPath.replace(packagePath, "");

        // 服务器持有证书链
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");

        String serverKeyStoreFile = projectPath + "/server.p12";

        String svrPassphrase = "123456";

        char[] svrPassword = svrPassphrase.toCharArray();

        KeyStore serverKeyStore = KeyStore.getInstance("pkcs12");
        KeyStore.getDefaultType();

        serverKeyStore.load(new FileInputStream(serverKeyStoreFile), svrPassword);

        kmf.init(serverKeyStore, svrPassword);

        SSLContext sslContext = SSLContext.getInstance("SSL");

        // 服务器信任证书链
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");

        String clientKeyStoreFile = projectPath + "/ca.p12";

        String cntPassphrase = "123456";

        char[] cntPassword = cntPassphrase.toCharArray();

//        KeyStore clientKeyStore = KeyStore.getInstance(KS_TYPE);
        KeyStore clientKeyStore = KeyStore.getInstance("pkcs12");

        clientKeyStore.load(new FileInputStream(clientKeyStoreFile), cntPassword);

        tmf.init(clientKeyStore);

        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLParameters defaultSSLParameters = sslContext.getDefaultSSLParameters();
        defaultSSLParameters.setNeedClientAuth(true);

        return sslContext;
    }

    static class MyHttpsConfigurator extends HttpsConfigurator {

        /**
         * Creates an Https configuration, with the given SSLContext.
         *
         * @param context the SSLContext to use for this configurator
         * @throws NullPointerException if no SSLContext supplied
         */
        public MyHttpsConfigurator(SSLContext context) {
            super(context);
        }

        @Override
        public void configure(HttpsParameters params) {
            // 设置需要验证客户端证书，
//            SSLContext sslContext = getSSLContext();
//            SSLParameters  sslParams = sslContext.getDefaultSSLParameters();
//            sslParams.setNeedClientAuth(true);
//            params.setSSLParameters(sslParams);

            super.configure(params);
        }
    }
}

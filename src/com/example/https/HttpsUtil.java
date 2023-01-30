package com.example.https;


import javax.net.ssl.*;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Map;

public class HttpsUtil {

//    private static final Logger LOGGER = LoggerFactory.getLogger(HttpsUtil.class);

    private static String charset = "utf-8";
    private static class TrustAnyTrustManager implements X509TrustManager {

        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
        }

        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[] {};
        }
    }

    private static class TrustAnyHostnameVerifier implements HostnameVerifier {
        public boolean verify(String hostname, SSLSession session) {
            System.out.println("hostname: " + hostname);
            return true;
        }
    }

    /**
     * post方式请求服务器(https协议)
     *
     * @param url
     *            请求地址
     * @param content
     *            参数
     *            编码
     * @return
     */
    public static String post(String url, String content, Map<String,String> headers, int connTimeOut, int soTimeOut ) {

        SSLContext sc =null; //构造一个sslcontext上下文，这个上下文里记录了会信任哪些服务器的证书以及自己上传的证书
        try{
            sc=SSLContext.getInstance("SSL");
            sc.init(null, new TrustManager[] { new TrustAnyTrustManager() },
                    new java.security.SecureRandom());
        }catch (Exception e){
//            LOGGER.error("getSSLContextError: ", e);
//            return URLConnUtil.EXCEPTION_MAP.get("GET_SSL_EXCEPTION");
            e.printStackTrace();
        }


        URL console =null;

        try{
            console=new URL(url);
        }catch (Exception e){
//            LOGGER.error("urlException: ", e);
//            return URLConnUtil.EXCEPTION_MAP.get("URI_SYNTAX_EXCEPTION");
            e.printStackTrace();
        }
        HttpsURLConnection conn =null;
        try{
            conn=(HttpsURLConnection) console.openConnection();
        }catch (Exception e){
//            LOGGER.error("IO_EXCEPTION: ", e);
//            return URLConnUtil.EXCEPTION_MAP.get("IO_EXCEPTION");
            e.printStackTrace();
        }

        //conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        if(headers!=null){
            Iterator<String> keys= headers.keySet().iterator();
            while(keys.hasNext()){
                String key=keys.next();
                conn.setRequestProperty(key,headers.get(key));
            }
        }

        conn.setSSLSocketFactory(sc.getSocketFactory());  //把初始化的上下文作为https 连接的一个属性设置进去
        conn.setHostnameVerifier(new TrustAnyHostnameVerifier()); // 设置连接是否校验 hostname
        conn.setDoOutput(true);
        conn.setConnectTimeout(connTimeOut);
        conn.setReadTimeout(soTimeOut);
        try{
            conn.connect();
        }catch (Exception e){
//            LOGGER.error("IO_EXCEPTION: ", e);
//            return URLConnUtil.EXCEPTION_MAP.get("IO_EXCEPTION");
            e.printStackTrace();
        }
        try {
            DataOutputStream out=new DataOutputStream(conn.getOutputStream());
            out.write(content.getBytes(charset));
            // 刷新、关闭
            out.flush();
            out.close();
            InputStream is = conn.getInputStream();
            if (is != null) {
                ByteArrayOutputStream outStream = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int len = 0;
                while ((len = is.read(buffer)) != -1) {
                    outStream.write(buffer, 0, len);
                }
                is.close();
                return new String(outStream.toByteArray());
            }
            return null;
        }catch (Exception e) {
//            LOGGER.error("IO_EXCEPTION: ", e);
//            return URLConnUtil.EXCEPTION_MAP.get("ConnectTimeoutException");
            e.printStackTrace();
        }
        return null;
    }
}
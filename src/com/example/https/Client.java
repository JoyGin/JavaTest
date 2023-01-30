package com.example.https;

public class Client {

    public static void main(String[] args) {
        String retMsg = HttpsUtil.post("https://127.0.0.1:8080/myserver", "111", null, 1000, 1000);
        System.out.println("客户端接收到返回消息：" + retMsg);
    }
}

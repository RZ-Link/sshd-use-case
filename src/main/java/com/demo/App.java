package com.demo;

import cn.hutool.core.collection.ListUtil;
import cn.hutool.core.thread.ThreadUtil;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.session.ClientSession;

import java.io.*;
import java.util.List;


public class App {
    public static void main(String[] args) {
//        System.out.println(exec("172.16.128.190", 22, "administrator", "bane@7766", "rule show id 1"));

        System.out.println(exec("172.16.128.190", 22, "administrator", "bane@7766", ListUtil.of("rule show", "rule show id 1")));
    }

    /**
     * SSH连接系统执行命令，获取结果
     *
     * @param host     ip
     * @param port     端口
     * @param username 用户名
     * @param password 密码
     * @param command  命令
     * @return 命令执行结果
     */
    public static String exec(String host, Integer port, String username, String password, String command) {
        StringBuilder result = new StringBuilder();

        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        try {
            // session密码登录
            ClientSession session = client.connect(username, host, port)
                    .verify(20000)
                    .getSession();
            session.addPasswordIdentity(password);
            session.auth().verify(20000);

            // channel合并STDOUT/STDERR流
            ClientChannel channel = session.createShellChannel();
            channel.setRedirectErrorStream(true);
            channel.open().verify(5000);

            // 获取SSH输入输出流，进行读写
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(channel.getInvertedIn()));
            BufferedReader reader = new BufferedReader(new InputStreamReader(channel.getInvertedOut()));

            // 启动线程持续输入空格回车
            Thread thread = ThreadUtil.newThread(() -> {
                while (true) {
                    try {
                        Thread.sleep(1000);
                        synchronized (writer) {
                            writer.write(" ");
                            writer.write("\n");
                            writer.flush();
                        }
                    } catch (Exception e) {
                        break;
                    }
                }
            }, "");
            thread.start();

            // 过滤欢迎、介绍内容，例如Welcome to Security Gateway
            // ==========================================
            //      Welcome to Security Gateway
            // ==========================================
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().endsWith("ac>")) {
                    break;
                }
            }

            // 输入命令
            synchronized (writer) {
                writer.write(command);
                writer.write("\n");
                writer.flush();
            }

            // 获取输出结果
            while ((line = reader.readLine()) != null) {
                result.append(line).append(System.lineSeparator());
                if (result.toString().trim().endsWith("ac>") && result.toString().contains(command)) {
                    break;
                }
            }

            // 关闭持续输入空格回车线程
            thread.interrupt();

            channel.close();
            session.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

        client.stop();

        return result.toString();
    }

    /**
     * SSH连接系统批量执行命令，获取结果
     *
     * @param host     ip
     * @param port     端口
     * @param username 用户名
     * @param password 密码
     * @param commands 命令列表
     * @return 命令执行结果
     */
    public static String exec(String host, Integer port, String username, String password, List<String> commands) {
        StringBuilder result = new StringBuilder();

        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        try {
            // session密码登录
            ClientSession session = client.connect(username, host, port)
                    .verify(20000)
                    .getSession();
            session.addPasswordIdentity(password);
            session.auth().verify(20000);

            // channel合并STDOUT/STDERR流
            ClientChannel channel = session.createShellChannel();
            channel.setRedirectErrorStream(true);
            channel.open().verify(5000);

            // 获取SSH输入输出流，进行读写
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(channel.getInvertedIn()));
            BufferedReader reader = new BufferedReader(new InputStreamReader(channel.getInvertedOut()));

            // 启动线程持续输入空格回车
            Thread thread = ThreadUtil.newThread(() -> {
                while (true) {
                    try {
                        Thread.sleep(1000);
                        synchronized (writer) {
                            writer.write(" ");
                            writer.write("\n");
                            writer.flush();
                        }
                    } catch (Exception e) {
                        break;
                    }
                }
            }, "");
            thread.start();

            // 过滤欢迎、介绍内容，例如Welcome to Security Gateway
            // ==========================================
            //      Welcome to Security Gateway
            // ==========================================
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().endsWith("ac>")) {
                    break;
                }
            }

            for (String command : commands) {
                // 输入命令
                synchronized (writer) {
                    writer.write(command);
                    writer.write("\n");
                    writer.flush();
                }
                // 获取输出结果
                while ((line = reader.readLine()) != null) {
                    result.append(line).append(System.lineSeparator());
                    if (result.toString().trim().endsWith("ac>") && result.toString().contains(command)) {
                        break;
                    }
                }
            }

            // 关闭持续输入空格回车线程
            thread.interrupt();

            channel.close();
            session.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

        client.stop();

        return result.toString();
    }


}

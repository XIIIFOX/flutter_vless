package com.github.tfox.flutter_vless.adversary;

import android.app.Activity;
import android.app.Instrumentation;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.util.Base64;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileDescriptor;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/** Separate installed application; the only credentials below belong to a disposable test runtime. */
public final class Probe extends Instrumentation {
    private static final String USER = "boundary-test-user";
    private static final String PASS = "boundary-test-password-never-production";
    private static final String MARKER = "flutter-vless-separate-uid-control";
    private Bundle args;
    private int socksPort, httpPort, originPort;
    private String broker;
    private int brokerConnected, brokerOsDenied;

    @Override public void onCreate(Bundle arguments) { args = arguments; start(); }

    private Socket socket(int port) throws Exception {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress("127.0.0.1", port), 3000);
        socket.setSoTimeout(3000);
        return socket;
    }

    private byte[] account(String password) {
        byte[] user = USER.getBytes(StandardCharsets.US_ASCII), pass = password.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(1); out.write(user.length); out.write(user, 0, user.length);
        out.write(pass.length); out.write(pass, 0, pass.length);
        return out.toByteArray();
    }

    private boolean noauthDenied() throws Exception {
        try (Socket socket = socket(socksPort)) {
            socket.getOutputStream().write(new byte[]{5, 1, 0});
            DataInputStream input = new DataInputStream(socket.getInputStream());
            return input.readUnsignedByte() == 5 && input.readUnsignedByte() == 255;
        }
    }

    private boolean wrongDenied() throws Exception {
        try (Socket socket = socket(socksPort)) {
            // Offering noauth alongside password must never allow a fallback.
            socket.getOutputStream().write(new byte[]{5, 2, 0, 2});
            DataInputStream input = new DataInputStream(socket.getInputStream());
            if (input.readUnsignedByte() != 5 || input.readUnsignedByte() != 2) return false;
            socket.getOutputStream().write(account("wrong-boundary-password"));
            return input.readUnsignedByte() == 1 && input.readUnsignedByte() != 0;
        }
    }

    private String response(Socket socket) throws Exception {
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int size;
        while ((size = socket.getInputStream().read(buffer)) != -1) {
            data.write(buffer, 0, size);
            if (data.size() > 16384) throw new IllegalStateException("Oversized test response");
        }
        return data.toString("US-ASCII");
    }

    private boolean socksControl() throws Exception {
        try (Socket socket = socket(socksPort)) {
            socket.getOutputStream().write(new byte[]{5, 1, 2});
            DataInputStream input = new DataInputStream(socket.getInputStream());
            if (input.readUnsignedByte() != 5 || input.readUnsignedByte() != 2) return false;
            socket.getOutputStream().write(account(PASS));
            if (input.readUnsignedByte() != 1 || input.readUnsignedByte() != 0) return false;
            socket.getOutputStream().write(new byte[]{5, 1, 0, 1, 127, 0, 0, 1, (byte)(originPort >> 8), (byte)originPort});
            if (input.readUnsignedByte() != 5 || input.readUnsignedByte() != 0 || input.readUnsignedByte() != 0) return false;
            int type = input.readUnsignedByte();
            int length = type == 1 ? 4 : type == 4 ? 16 : type == 3 ? input.readUnsignedByte() : -1;
            if (length < 0) return false;
            input.readFully(new byte[length + 2]);
            socket.getOutputStream().write("GET /socks-control HTTP/1.1\r\nHost: boundary.test\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            return response(socket).contains(MARKER);
        }
    }

    private String http(String password) throws Exception {
        try (Socket socket = socket(httpPort)) {
            String auth = password == null ? "" : "Proxy-Authorization: Basic " + Base64.encodeToString((USER + ":" + password).getBytes(StandardCharsets.US_ASCII), Base64.NO_WRAP) + "\r\n";
            socket.getOutputStream().write(("GET http://127.0.0.1:" + originPort + "/http-control HTTP/1.1\r\nHost: boundary.test\r\n" + auth + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            return response(socket);
        }
    }

    private boolean brokerDenied(int command) throws Exception {
        try (LocalSocket socket = new LocalSocket()) {
            // A successful connect distinguishes peer authorization from an absent listener.
            try {
                socket.connect(new LocalSocketAddress(broker, LocalSocketAddress.Namespace.ABSTRACT));
                brokerConnected++;
            } catch (java.io.IOException denied) {
                Throwable cause = denied;
                while (cause != null) {
                    if (cause instanceof android.system.ErrnoException) {
                        int errno = ((android.system.ErrnoException) cause).errno;
                        if (errno == android.system.OsConstants.EACCES || errno == android.system.OsConstants.EPERM) {
                            brokerOsDenied++; return true;
                        }
                    }
                    cause = cause.getCause();
                }
                // Some Android LocalSocket versions flatten ErrnoException into IOException.
                if (denied.getMessage() != null && (denied.getMessage().contains("EACCES") || denied.getMessage().contains("Permission denied"))) {
                    brokerOsDenied++; return true;
                }
                throw denied;
            }
            socket.setSoTimeout(3000);
            ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
            try {
                if (command == 'H' || command == 'P') socket.setFileDescriptorsForSend(new FileDescriptor[]{pipe[0].getFileDescriptor()});
                try {
                    socket.getOutputStream().write(command);
                    if (command == 'D') {
                        byte[] query = {0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 97, 4, 116, 101, 115, 116, 0, 0, 1, 0, 1};
                        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                        out.writeShort(query.length); out.write(query);
                    }
                    int reply = socket.getInputStream().read();
                    return command == 'D' ? reply == -1 : reply != 1;
                } catch (java.net.SocketTimeoutException timeout) {
                    return false;
                } catch (java.io.IOException closedByPeer) {
                    // Same-UID positive control and host protect-call counter are checked separately.
                    return true;
                }
            } finally { pipe[0].close(); pipe[1].close(); }
        }
    }

    /** Shell has a different UID but can reach an app's abstract socket on this emulator.
     * It tests the broker's peer-UID guard separately from cross-app SELinux denial. */
    public static void main(String[] values) {
        JSONObject report = new JSONObject();
        boolean passed = false;
        try {
            Probe probe = new Probe(); probe.broker = values[0];
            int hostUid = Integer.parseInt(values[1]);
            report.put("probe", "shell-broker"); report.put("uid", Process.myUid()); report.put("host_uid", hostUid);
            report.put("handshake_denied", probe.brokerDenied('H'));
            report.put("protect_denied", probe.brokerDenied('P'));
            report.put("dns_denied", probe.brokerDenied('D'));
            report.put("connected_requests", probe.brokerConnected);
            report.put("os_denied_connections", probe.brokerOsDenied);
            report.put("peer_uid_guard_exercised", probe.brokerConnected == 3);
            report.put("denial_layer", probe.brokerOsDenied == 3 ? "android_access_control_before_connect" : "connected_socket_peer_authorization");
            passed = Process.myUid() != hostUid && (probe.brokerConnected == 3 || probe.brokerOsDenied == 3) &&
                report.getBoolean("handshake_denied") && report.getBoolean("protect_denied") && report.getBoolean("dns_denied");
        } catch (Exception error) {
            try { report.put("error_class", error.getClass().getSimpleName()); } catch (Exception ignored) { }
        }
        try { report.put("passed", passed); } catch (Exception ignored) { }
        System.out.println(report.toString());
        System.exit(passed ? 0 : 1);
    }

    private void httpProbeMode() {
        JSONObject report = new JSONObject();
        boolean success = false, blocked = false, connected = false;
        try {
            report.put("adversary_uid", Process.myUid()); report.put("mode", "httpProbe");
            java.net.URI uri = new java.net.URI(args.getString("url", "http://10.0.2.2:18083/"));
            if (!"http".equals(uri.getScheme()) || !"10.0.2.2".equals(uri.getHost()) || uri.getPort() != 18083 || uri.getRawUserInfo() != null)
                throw new IllegalArgumentException("Only controlled host-loopback marker fixture is supported");
            int timeout = Math.max(100, Math.min(5000, Integer.parseInt(args.getString("timeout", "1500"))));
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("10.0.2.2", 18083), timeout);
                connected = true;
                socket.setSoTimeout(timeout);
                socket.getOutputStream().write("GET / HTTP/1.1\r\nHost: 10.0.2.2:18083\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                success = response(socket).contains("flutter-vless-direct-bypass");
            } catch (java.io.IOException denied) {
                blocked = true;
                report.put("error_class", denied.getClass().getSimpleName());
            }
        } catch (Exception error) {
            try { report.put("error_class", error.getClass().getSimpleName()); } catch (Exception ignored) { }
        }
        try { report.put("success", success); report.put("blocked", blocked); report.put("connected", connected); } catch (Exception ignored) { }
        Bundle output = new Bundle(); output.putString("report", report.toString());
        finish(Activity.RESULT_OK, output);
    }

    @Override public void onStart() {
        if ("httpProbe".equals(args.getString("mode"))) { httpProbeMode(); return; }
        JSONObject report = new JSONObject();
        boolean passed = false;
        try {
            socksPort = Integer.parseInt(args.getString("socksPort"));
            httpPort = Integer.parseInt(args.getString("httpPort"));
            originPort = Integer.parseInt(args.getString("originPort"));
            broker = args.getString("broker");
            int hostUid = Integer.parseInt(args.getString("hostUid"));
            report.put("adversary_uid", Process.myUid()); report.put("host_uid", hostUid);
            report.put("different_uid", Process.myUid() != hostUid);
            report.put("socks_noauth_denied", noauthDenied());
            report.put("socks_wrong_password_denied", wrongDenied());
            report.put("socks_authenticated_control", socksControl());
            report.put("http_noauth_denied", http(null).startsWith("HTTP/1.1 407"));
            report.put("http_wrong_password_denied", http("wrong-boundary-password").startsWith("HTTP/1.1 407"));
            report.put("http_authenticated_control", http(PASS).contains(MARKER));
            report.put("broker_handshake_fd_denied", brokerDenied('H'));
            report.put("broker_protect_fd_denied", brokerDenied('P'));
            report.put("broker_dns_denied", brokerDenied('D'));
            report.put("broker_connected_requests", brokerConnected);
            report.put("broker_os_denied_connections", brokerOsDenied);
            report.put("broker_denial_layer", brokerOsDenied == 3 ? "android_access_control_before_connect" : "connected_socket_peer_authorization");
            passed = true;
            for (String key : new String[]{"different_uid", "socks_noauth_denied", "socks_wrong_password_denied", "socks_authenticated_control", "http_noauth_denied", "http_wrong_password_denied", "http_authenticated_control", "broker_handshake_fd_denied", "broker_protect_fd_denied", "broker_dns_denied"}) passed &= report.getBoolean(key);
        } catch (Exception error) {
            try { report.put("error_class", error.getClass().getSimpleName()); } catch (Exception ignored) { }
        }
        try { report.put("passed", passed); } catch (Exception ignored) { }
        Bundle output = new Bundle(); output.putString("report", report.toString());
        finish(passed ? Activity.RESULT_OK : Activity.RESULT_CANCELED, output);
    }
}

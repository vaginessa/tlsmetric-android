package de.felixschiller.tlsmetric.Assistant;

import android.app.ActivityManager;
import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

import de.felixschiller.tlsmetric.PacketAnalyze.AnalyzerService;
import de.felixschiller.tlsmetric.R;

/**
 * All the litte helpers of this app
 */
public class ToolBox{

    private static final char[] hexCode = "0123456789ABCDEF".toCharArray();

    public static String printHexBinary(byte[] data) {
        StringBuilder r = new StringBuilder(data.length * 2);
        for (byte b : data) {
            r.append(hexCode[(b >> 4) & 0xF]);
            r.append(hexCode[(b & 0xF)]);
        }
        return r.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    public static String printExportHexString(byte[] data) {
        String hexString = printHexBinary(data);
        String export = "000000 ";
        for (int i = 0; i + 1 < hexString.length(); i += 2) {
            export += " " + hexString.substring(i, i + 2);
        }
        export += " ......";
        return export;
    }

    // Returns active Network interfaces
    public String getIfs(Context context){
        //read from command: netcfg | grep UP

        String filePath = context.getFilesDir().getAbsolutePath() + File.separator + Const.FILE_IF_LIST;
        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Try to get active interfaces to" + filePath);
        ExecuteCommand.user("rm " + filePath);
        ExecuteCommand.user("netcfg | grep UP -> " + filePath);
        String result = ExecuteCommand.userForResult("cat " + filePath);
        return result;
    }

    private int hexToBin(char ch) {
        if ('0' <= ch && ch <= '9') return ch - '0';
        if ('A' <= ch && ch <= 'F') return ch - 'A' + 10;
        if ('a' <= ch && ch <= 'f') return ch - 'a' + 10;
        return -1;
    }

    public static InetAddress getLocalAddress(){
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
                 en.hasMoreElements();) {
                NetworkInterface intf = en.nextElement();
                for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements();) {
                    InetAddress inetAddress = enumIpAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress()) {
                        return inetAddress;
                    }
                }
            }
        } catch (Exception e) {
            Log.e(Const.LOG_TAG, "Error while obtaining local address");
            e.printStackTrace();
        }
        return null;
    }

    public static boolean isAnalyzerServiceRunning() {
        ActivityManager manager = (ActivityManager)ContextSingleton.getContext().getSystemService(Context.ACTIVITY_SERVICE);
        for (ActivityManager.RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
            if (AnalyzerService.class.getName().equals(service.service.getClassName())) {
                return true;
            }
        }
        return false;
    }

}

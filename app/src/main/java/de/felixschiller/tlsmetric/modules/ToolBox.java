package de.felixschiller.tlsmetric.modules;

import android.content.Context;
import android.util.Log;

import com.stericson.RootShell.exceptions.RootDeniedException;
import com.stericson.RootShell.execution.Command;
import com.stericson.RootTools.RootTools;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.TimeoutException;

import de.felixschiller.tlsmetric.R;
import de.felixschiller.tlsmetric.helper.Const;

/**
 * All the litte helpers of this app
 */
public class ToolBox{

    private static File mFile;
    private static String mBinPath;
    private static String mFilePath;

    public static void initPaths(Context context){
        mFile = new File(context.getFilesDir(), Const.FILE_PCAP);
        mBinPath = context.getFilesDir().getAbsolutePath() + File.separator + Const.FILE_TCPDUMP;
        mFilePath = context.getFilesDir().getAbsolutePath() + File.separator + Const.FILE_PCAP;
    }

    public static File getDumpFile(){
            return mFile;
    }
    public static String getDumpFileString(){
        return mFilePath;
    }

    // Returns network information
    // TODO: Modify to get available interfaces.
    public String getIfs(Context context){
        //read from command: netcfg | grep UP

        String filePath = context.getFilesDir().getAbsolutePath() + File.separator + Const.FILE_IF_LIST;
        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Try to get active interfaces to" + filePath);
        userCommand.doCommand(0, "rm " + filePath);
        userCommand.doCommand(0, "netcfg | grep UP -> " + filePath);
        userCommand.doCommand(0, "cat " + filePath);
        //TODO: Creating the file works, to the parse in java
        return "rmnet0";
    }
    //copy the tcpdump binary to /system/bin folder
    public void deployTcpDump(Context context){
        String binPath = context.getFilesDir().getAbsolutePath() + File.separator + Const.FILE_TCPDUMP;
        File file = new File(binPath);
        try {
            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Extract tcpdump.");
            InputStream in = context.getResources().openRawResource(R.raw.tcpdump);
            byte[] buffer = new byte[in.available()];
            in.read(buffer);
            OutputStream out = new FileOutputStream(binPath);
            out.write(buffer);
        } catch (Exception e) {
            Log.e(Const.LOG_TAG, "Deserialization of binary files failed", e);
        }
        Command command = new Command(3, "chmod 6755 " + mBinPath);
        try {
            RootTools.getShell(true).add(command);
        } catch (IOException | TimeoutException | RootDeniedException e) {
            e.printStackTrace();
        }
        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "chmod 6755 " + mBinPath);
    }

    /*
     *SYNOPSIS

       tcpdump [ -AdDeflLnNOpqRStuUvxX ] [ -c count ]
               [ -C file_size ] [ -F file ]
               [ -i interface ] [ -m module ] [ -M secret ] [ -r file ]
               [ -s snaplen ] [ -T type ] [ -w file ]
               [ -W filecount ] [ -E spi@ipaddr algo:secret,...  ]
               [ -y datalinktype ] [ -Z user ]
      [ expression ]

     */
    //Run dump on active interface.
    public void runTcpDump(Context context){
        String parameter = " -w " + Const.FILE_PCAP;
        //userCommand.doCommand(0, mBinPath + parameter);
        Command command = new Command(3, mBinPath);
        try {
            RootTools.getShell(true).add(command);
        } catch (IOException | TimeoutException | RootDeniedException e) {
            e.printStackTrace();
        }
        //RootTools.runBinary(context, mBinPath, "");
        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, mBinPath);
    }
    //Run dump on specific interface.
    public void stopTcpDump(){
        //Kill it with Fire!
        //userCommand.doCommand(0, "kill -s 1 tcpdump");
        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "kill -s 1 tcpdump");
    }
    private int hexToBin(char ch) {
        if ('0' <= ch && ch <= '9') return ch - '0';
        if ('A' <= ch && ch <= 'F') return ch - 'A' + 10;
        if ('a' <= ch && ch <= 'f') return ch - 'a' + 10;
        return -1;
    }

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

    public static String printExportHexString(byte[] data){
        String hexString = printHexBinary(data);
        String export = "000000 ";
        for(int i = 0; i+1 < hexString.length(); i += 2){
            export += " " + hexString.substring(i, i+2);
        }
        export += " ......";
        return export;
    }

}

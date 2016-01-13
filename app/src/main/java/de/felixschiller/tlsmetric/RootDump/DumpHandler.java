package de.felixschiller.tlsmetric.RootDump;

import android.content.Context;
import android.content.Intent;
import android.util.Log;
import android.widget.Toast;

import com.stericson.RootTools.RootTools;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.Assistant.ContextSingleton;
import de.felixschiller.tlsmetric.Assistant.ExecuteCommand;
import de.felixschiller.tlsmetric.PacketAnalyze.AnalyzerService;
import de.felixschiller.tlsmetric.R;

/**
 * Created by schillef on 10.01.2016.
 */
public class DumpHandler {
    private static File mFile;
    private static File mBin;
    private static String mBinPath;
    private static String mFilePath;

    public DumpHandler(){
        mFile = new File(ContextSingleton.getContext().getFilesDir(), Const.FILE_PCAP);
        mBin = new File(ContextSingleton.getContext().getFilesDir(), Const.FILE_TCPDUMP);
        mBinPath = ContextSingleton.getContext().getFilesDir().getAbsolutePath() + File.separator + Const.FILE_TCPDUMP;
        mFilePath = ContextSingleton.getContext().getFilesDir().getAbsolutePath() + File.separator + Const.FILE_PCAP;
    }

    //start the tcpdump process
    public void start(){
        if (!mBin.exists()){
            deployTcpDump(ContextSingleton.getContext());
        } else {
            if(Const.IS_DEBUG) Log.d(Const.LOG_TAG, "tcpdump present.");
        }
        if (mFile.exists()){
            deletePcapFile();
        }

        String command = DumpHandler.generateCommand();
        //Start tcp dump with su rights
        if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Start tcpdump. : " + command);
        ExecuteCommand.sudo(command);
        /*try{
            Process su = Runtime.getRuntime().exec("su");
            DataOutputStream os = new DataOutputStream(su.getOutputStream());
            os.writeBytes(command);
            os.flush();
            os.writeBytes("exit\n");
            os.flush();
            os.close();
        } catch (IOException e) {
            e.printStackTrace();
        }*/

    }

    //stop the tcpdump process
    public void stop(){
        ExecuteCommand.sudo("killall tcpdump");
    }

    //restart the tcpdump process
    public void restart(){
        stop();
        start();
    }

    //Extract the tcpdump binary to /system/bin folder
    public void deployTcpDump(Context context){
        try {
            if(Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Extract tcpdump.");
            InputStream in = context.getResources().openRawResource(R.raw.tcpdump);
            byte[] buffer = new byte[in.available()];
            in.read(buffer);
            OutputStream out = new FileOutputStream(mBin);
            out.write(buffer);
        } catch (Exception e) {
            Log.e(Const.LOG_TAG, "Deserialization of binary files failed", e);
        }
        ExecuteCommand.user("chmod 6755 " + mBinPath);
    }

        /*Run dump on active interface.
    -----------------------------------------------------------------
     *SYNOPSIS

       tcpdump [ -AdDeflLnNOpqRStuUvxX ] [ -c count ]
               [ -C file_size ] [ -F file ]
               [ -i interface ] [ -m module ] [ -M secret ] [ -r file ]
               [ -s snaplen ] [ -T type ] [ -w file ]
               [ -W filecount ] [ -E spi@ipaddr algo:secret,...  ]
               [ -y datalinktype ] [ -Z user ]
      [ expression ]
     */

    public static String generateCommand() {
        return mBinPath + " " + Const.PARAMS + " " + mFilePath + " &";
    }

    public static void deletePcapFile(){
        deleteFile(mFile);
    }

    public static void deleteTcpDumpBin(){
        deleteFile(mBin);
    }

    private static void deleteFile(File file){
        try{
            if(file.delete()){
                if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, file.getName() + " is deleted!");
            }else{
                Log.e(Const.LOG_TAG, "Delete operation failed!");
            }
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public void startAnalyzerService(){
        for(int i = 0; i < 10; i++){
            if(mFile.exists()) {
                if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Dump file present, edit permissions.");
                ExecuteCommand.sudo("chmod 6755 " + mFilePath);
                Intent intent = new Intent(ContextSingleton.getContext(), AnalyzerService.class);
                ContextSingleton.getActivity().startService(intent);
                break;
            } else {
                Log.i(Const.LOG_TAG, mFile.getAbsolutePath() + "does not exist. Wait for dump process " + (10 - i) + " times...");
                if(i == 9) {
                    Log.e(Const.LOG_TAG, mFile.getAbsolutePath() + "does not exist. Service not started");
                }
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public void stopAnalyzerService(){
        Intent intent = new Intent(ContextSingleton.getContext(), AnalyzerService.class);
        ContextSingleton.getContext().stopService(intent);
    }



    //Checks for su rights
    public void checkSu() {
        if (RootTools.isRootAvailable()) {
            Toast toast = Toast.makeText(ContextSingleton.getContext(), "Superuser is installed.", Toast.LENGTH_LONG);
            toast.show();
        } else {
            Toast toast = Toast.makeText(ContextSingleton.getContext(), "Superuser is NOT installed. \n" +
                    "opening download screen", Toast.LENGTH_LONG);
            toast.show();
            //TODO: Does not Work, Why?
            //RootTools.offerSuperUser(MainActivity.sActivity);
        }
    }




}

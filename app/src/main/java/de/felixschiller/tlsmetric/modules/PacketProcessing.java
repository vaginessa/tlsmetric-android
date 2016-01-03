package de.felixschiller.tlsmetric.modules;

import android.util.Log;

import de.felixschiller.tlsmetric.helper.Const;

/**
 * Reads network packages from dumpfiles or stream and processes them by given filters.
 */
public class PacketProcessing extends Thread {
    final StringBuilder errbuf = new StringBuilder(); // For any error msgs
    private static String sFilePath;
    public PacketProcessing(String filePath){
        sFilePath = filePath;
    }
    //private Context mContext;

   /*
    public void init(Context context, Boolean isRoot) {
        mContext = context;
        if (isRoot) {
            //TODO: init Root stuff
        } else {
            //TODO: init VPN stuff
        }
    }*/

    public void run() {

        //TODO: implementation some kind of file rotation needed?

        try {
            sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}

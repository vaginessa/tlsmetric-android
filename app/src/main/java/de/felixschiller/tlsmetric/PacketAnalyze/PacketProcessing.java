package de.felixschiller.tlsmetric.PacketAnalyze;

/**
 * Reads network packages from dumpfiles or stream and processes them by given filters.
 */
public class PacketProcessing extends Thread {
    private static String sFilePath;
    final StringBuilder errbuf = new StringBuilder(); // For any error msgs
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

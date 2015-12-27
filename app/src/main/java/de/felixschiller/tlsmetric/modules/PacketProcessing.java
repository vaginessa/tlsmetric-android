package de.felixschiller.tlsmetric.modules;

import android.util.Log;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.tcpip.Http;

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
        if (Const.IS_DEBUG)
            Log.d(Const.LOG_TAG, "Opening file for reading: %s%n " + sFilePath);
        Pcap pcap = Pcap.openOffline(sFilePath, errbuf);
        if (pcap == null) {
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            public void nextPacket(PcapPacket packet, String warning) {

                //TODO: implement messaging service to app!
                //TODO: implement central filter management
                if (packet.hasHeader(Http.ID)) {
                    //Toast.makeText(mContext, "Unencrypted http present " + packet.getCaptureHeader().toString(), Toast.LENGTH_LONG);
                    if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Unencrypted Http present");
                }
            }
        };
        int i = 1;
        while (i > 0)
            i = pcap.dispatch(1, 01, jpacketHandler, "State a statement.");

        try {
            sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}

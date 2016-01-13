package de.felixschiller.tlsmetric.PacketAnalyze;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.util.Log;
import android.widget.Toast;

import com.voytechs.jnetstream.codec.Decoder;
import com.voytechs.jnetstream.codec.Packet;

import com.voytechs.jnetstream.io.EOPacketStream;
import com.voytechs.jnetstream.io.RawformatInputStream;
import com.voytechs.jnetstream.io.StreamFormatException;
import com.voytechs.jnetstream.npl.SyntaxError;

import java.io.File;
import java.io.IOException;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.Assistant.ContextSingleton;


/**
 * Created by schillef on 10.01.2016.
 */
public class AnalyzerService extends Service {

    private Thread mThread;
    private Decoder mDecoder;
    private RawformatInputStream mRawIn;
    private boolean isVpn;

    @Override
    public void onCreate() {
        try {
        if(isVpn){
            //TODO: Init mDecoder set to CloneBuffer
        } else {
            File file = new File(ContextSingleton.getContext().getFilesDir(), Const.FILE_PCAP);
            if(file.exists()) {
                mRawIn = new RawformatInputStream(file.getAbsolutePath());
                mDecoder = new Decoder(mRawIn);
            } else{
                Log.e(Const.LOG_TAG, "Could not find raw Dump file " + file.getAbsolutePath());
            }
        }
        } catch (IOException | SyntaxError | EOPacketStream | StreamFormatException e) {
            e.printStackTrace();
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i("LocalService", "Received start id " + startId + ": " + intent);
        // Stop the previous session by interrupting the thread.
        if (mThread != null) {
            mThread.interrupt();
        }
        //Analyzer working thread
        mThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Packet packet;
                    while ((packet = dumpNext()) != null) {
                        analyzePacket(packet);
                    }
                    Thread.sleep(50);
                } catch (StreamFormatException | SyntaxError | IOException | InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }, "NetworkDumpRunnable");

        //start the service
        mThread.start();
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        //TODO: rm pcap file
        // Tell the user we stopped.
        Toast.makeText(this, "Dump Service Stopped", Toast.LENGTH_SHORT).show();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return new AnalyzerBinder();
    }

    /*
     * Class for clients to access.  Because we know this service always
     * runs in the same process as its clients, we don't need to deal with
     * IPC.
     */
    public class AnalyzerBinder extends Binder {
        AnalyzerService getService() {
            return AnalyzerService.this;
        }
    }

    private Packet dumpNext() throws StreamFormatException, IOException, SyntaxError{
        Packet pkt;
        if(isVpn){
            //TODO: read from CloneBuffer
            return null;
        } else {
            //read from pcapFile
            if((pkt = mDecoder.nextPacket()) != null){
                return mDecoder.nextPacket();
            } else{
                return null;
            }
        }

    }

    private void analyzePacket(Packet pkt){
        //TODO: Analyzer Logic
        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, pkt.getSummary());
    }
}

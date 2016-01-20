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

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Date;
import java.util.LinkedList;
import java.util.Queue;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.Assistant.ContextSingleton;
import de.felixschiller.tlsmetric.RootDump.DumpHandler;


/**
 * Created by schillef on 10.01.2016.
 */
public class AnalyzerService extends Service {

    public static boolean mInterrupt;
    private Thread mThread;

    //JNETSTREAM stuff
    private Decoder mDecoder;
    private RawformatInputStream mRawIn;

    //JNETPCAP stuff
    final StringBuilder mErrbuf = new StringBuilder();
    private Pcap mPcap;
    PcapPacketHandler<String> mJpacketHandler;
    private Queue<JPacket> mPacketQueue;

    private File mDumpFile;
    private long mBufferPosition;


    private boolean mIsFileEmpty;
    private boolean isVpn;

    private PacketProcessing mProcess;

    @Override
    public void onCreate() {
        System.loadLibrary("jnetpcap");
        mInterrupt = false;
        mBufferPosition = 0;
        mProcess = new PacketProcessing();

        if(!isVpn){
            mDumpFile = new File(ContextSingleton.getContext().getFilesDir() + File.separator + Const.FILE_DUMP);
            //initDecoderWithDumpfile();
            initPcapWithDumpfile();
            mPacketQueue = new LinkedList<>();


        } else {
            //TODO: Init mDecoder set to CloneBuffer
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
                //TODO: Restart dumping mechanism if file gets too big
                try {
                    Packet packet;
                    while (!mInterrupt) {
                        //packet = dumpNext();
                        dumpNextPcap();
                        if(!mPacketQueue.isEmpty()){
                            analyzePacket(mPacketQueue.poll());
                            Thread.sleep(50);
                        } else {
                            Thread.sleep(500);
                            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Reinitialize dumpfile");
                            //initDecoderWithDumpfile();
                            initPcapWithDumpfile();
                        }
                    }
                } catch (SyntaxError | IOException | InterruptedException e) {
                    e.printStackTrace();
                }
                if(mInterrupt)mThread.interrupt();
                stopSelf();
            }
        }, "AnalyzerThreadRunnable");

        //start the service
        mThread.start();
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        DumpHandler.deleteDumpFile();
        Toast.makeText(this, "TLSMetric service stopped", Toast.LENGTH_SHORT).show();
        if(mPcap != null){
            mPcap.close();
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return new AnalyzerBinder();
    }

    /*
    * Returns the dumped Packet or null. Null means thread will sleep. If the dumpfile is empty a
    * new initialization attempt will be made.
     */
    private Packet dumpNext() throws IOException, SyntaxError {

        if (!isVpn && !mIsFileEmpty) {
            try {
                return mDecoder.nextPacket();
            } catch (StreamFormatException e) {
                if (Const.IS_DEBUG)
                    Log.d(Const.LOG_TAG, "No complete Packet in file, taking a little break...");
                e.printStackTrace();
                return null;
            }
        } else if (mIsFileEmpty) {
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "File is empty, try to init it again.");
            initDecoderWithDumpfile();
            return null;
        } else if (isVpn) {
            //TODO: VPN branch - read from CloneBuffer
            return null;
        }
        return null;
    }

    private void dumpNextPcap() throws IOException, SyntaxError {

        if (!isVpn && !mIsFileEmpty) {
                int code = mPcap.loop(1, mJpacketHandler, "TLSMetric");
                if (code < 0 && Const.IS_DEBUG)
                    Log.d(Const.LOG_TAG, "No complete Packet in file, taking a little break...");
        } else if (mIsFileEmpty) {
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "File is empty, try to init it again.");
            initDecoderWithDumpfile();
        } else if (isVpn) {
            //TODO: VPN branch - read from CloneBuffer
        }
    }

    private void analyzePacket(Packet pkt){
        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, pkt.getSummary());
        mProcess.processPacket(pkt);

    }

    private void analyzePacket(JPacket pkt){
        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, pkt.toString());
        mProcess.processPacket(pkt);
    }

    private void checkEmptyFile(File file) {
        try {
            FileInputStream fis = new FileInputStream(file);
            int b = fis.read();
            if (b == -1) {
                System.out.println("File " + file.getAbsolutePath() + " is empty!");
                mIsFileEmpty = true;
            } else {
                mIsFileEmpty = false;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void initDecoderWithDumpfile() {
        try {
            if (mDumpFile.exists()) {
                checkEmptyFile(mDumpFile);
                if(!mIsFileEmpty) {
                    mRawIn = new RawformatInputStream(mDumpFile.getAbsolutePath());
                    mRawIn.skip(mBufferPosition);
                    mDecoder = new Decoder(mRawIn);

                }
            } else{
                Log.e(Const.LOG_TAG, "Could not find raw Dump file " + mDumpFile.getAbsolutePath());
            }
        } catch (IOException | SyntaxError | EOPacketStream | StreamFormatException e) {
            e.printStackTrace();
        }
    }


    private void initPcapWithDumpfile() {
        if (mDumpFile.exists()) {
            checkEmptyFile(mDumpFile);
            if (!mIsFileEmpty) {
                if(mPcap != null){
                    mPcap.close();
                }
                mPcap = Pcap.openOffline(mDumpFile.getAbsolutePath(), mErrbuf);
                if (mPcap == null) {
                    if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Error while opening device for capture: "
                            + mErrbuf.toString());
                }

                mJpacketHandler = new PcapPacketHandler<String>() {
                    @Override
                    public void nextPacket(PcapPacket packet, String user) {
                        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, packet.toString());
                    }
                };
            } else {
                Log.e(Const.LOG_TAG, "Could not find raw Dump file " + mDumpFile.getAbsolutePath());
            }
        }
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


}

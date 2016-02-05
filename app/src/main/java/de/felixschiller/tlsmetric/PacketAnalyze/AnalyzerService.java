package de.felixschiller.tlsmetric.PacketAnalyze;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.app.TaskStackBuilder;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Binder;
import android.os.IBinder;
import android.support.v4.app.NotificationCompat;
import android.util.Log;
import android.widget.Toast;

import com.voytechs.jnetstream.codec.Decoder;
import com.voytechs.jnetstream.codec.Packet;
import com.voytechs.jnetstream.io.EOPacketStream;
import com.voytechs.jnetstream.io.RawformatInputStream;
import com.voytechs.jnetstream.io.StreamFormatException;
import com.voytechs.jnetstream.npl.SyntaxError;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import de.felixschiller.tlsmetric.Activities.EvidenceActivity;
import de.felixschiller.tlsmetric.Activities.MainActivity;
import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.Assistant.ContextSingleton;
import de.felixschiller.tlsmetric.R;
import de.felixschiller.tlsmetric.RootDump.DumpHandler;


/**
 * Packet Analyzer Service. Working with VPN- or Dump-core, set by boolean.
 */
public class AnalyzerService extends Service {

    public static boolean mInterrupt;
    private Thread mThread;
    private RawformatInputStream mRawIn;
    private Decoder mDecoder;
    private File mDumpFile;
    private long mBufferPosition;
    private boolean mIsFileEmpty;
    private boolean isVpn;
    private Evidence mEvidence = new Evidence();

    private int mNotificationCount;
    NotificationCompat.Builder mBuilder =
            new NotificationCompat.Builder(this)
                    .setSmallIcon(R.drawable.icon)
                    .setContentTitle("TLSMetric")
                    .setContentText("Packet analyzer service is running.");

    //private Bitmap mQuest;
    private Bitmap mOk;
    private Bitmap mWarnOrange;
    private Bitmap mWarnRed;


    @Override
    public void onCreate() {
        mInterrupt = false;
        isVpn = false;
        mBufferPosition = 0;
        mNotificationCount = 0;
        loadNotificationBitmaps();

        showAppNotification();

        if(!isVpn){
            mDumpFile = new File(ContextSingleton.getContext().getFilesDir() + File.separator + Const.FILE_DUMP);
            initDecoderWithDumpfile();
        } else {
            //VPN branch : Init mDecoder set to CloneBuffer
            Log.i(Const.LOG_TAG,"VPN core not yet implemented");
        }
    }

    private void loadNotificationBitmaps() {
        BitmapFactory.Options mBitmapOptions = new BitmapFactory.Options();
        mBitmapOptions.outWidth = 32;
        mBitmapOptions.outHeight = 32;
        //mQuest = BitmapFactory.decodeResource(getResources(), R.drawable.icon_quest, mBitmapOptions);
        mOk = BitmapFactory.decodeResource(getResources(), R.drawable.icon_ok, mBitmapOptions);
        mWarnOrange = BitmapFactory.decodeResource(getResources(), R.drawable.icon_warn_orange, mBitmapOptions);
        mWarnRed = BitmapFactory.decodeResource(getResources(), R.drawable.icon_warn_red, mBitmapOptions);


    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i("LocalService", "Received start id " + startId + ": " + intent);
        showAppNotification();
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
                    while (!mInterrupt) {
                        packet = dumpNext();
                        if(packet != null){
                            if(mEvidence.processPacket(packet)){
                                checkForNotifications();
                            }
                            Thread.sleep(50);
                        } else {
                            Thread.sleep(1000);
                            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Reinitialize dumpfile");
                            initDecoderWithDumpfile();
                        }
                        checkForNotifications();
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
        showNoNotification();
        DumpHandler.deleteDumpFile();
        Toast.makeText(this, "TLSMetric service stopped", Toast.LENGTH_SHORT).show();
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
            //if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "File is Empty. Reinitialize.");
            initDecoderWithDumpfile();
            return null;
        } else if (isVpn) {
            // VPN branch - read from CloneBuffer
            Log.i(Const.LOG_TAG,"VPN core not yet implemented");
            return null;
        }
        return null;
    }

    private void checkEmptyFile(File file) {
        try {
            FileInputStream fis = new FileInputStream(file);
            int b = fis.read();
            mIsFileEmpty = b == -1;
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
    private void checkForNotifications(){
        if(Evidence.newWarnings != mNotificationCount) {
            mNotificationCount = Evidence.newWarnings;
            if (mNotificationCount > 0) {
                showWarningNotification();
            } else {
                showAppNotification();
            }
        }
    }
    private void showAppNotification(){
        mBuilder.setSmallIcon(R.drawable.icon);
        mBuilder.setLargeIcon(mOk);
        // Creates an explicit intent for an Activity in your app
        Intent resultIntent = new Intent(this, MainActivity.class);

        // The stack builder object will contain an artificial back stack for the
        // started Activity.
        // This ensures that navigating backward from the Activity leads out of
        // your application to the Home screen.
        TaskStackBuilder stackBuilder = TaskStackBuilder.create(this);

        // Adds the back stack for the Intent (but not the Intent itself)
        stackBuilder.addParentStack(MainActivity.class);

        // Adds the Intent that starts the Activity to the top of the stack
        stackBuilder.addNextIntent(resultIntent);
        PendingIntent resultPendingIntent =
                stackBuilder.getPendingIntent(0, PendingIntent.FLAG_UPDATE_CURRENT);
        mBuilder.setContentIntent(resultPendingIntent);
        NotificationManager mNotificationManager =
                (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        // mId allows you to update the notification later on.
        mNotificationManager.notify(Const.LOG_TAG, 1, mBuilder.build());
    }

    private void showWarningNotification(){
        //Set corresponding icon
        if(Evidence.getMaxSeverity() > 2){
            mBuilder.setSmallIcon(R.drawable.icon_warn_red);
            mBuilder.setLargeIcon(mWarnRed);
        } else {
            mBuilder.setSmallIcon(R.drawable.icon_warn_orange);
            mBuilder.setLargeIcon(mWarnOrange);
        }
        mBuilder.setContentText(mNotificationCount + " new warnings encountered.");

        // Creates an explicit intent for an Activity in your app
        Intent resultIntent = new Intent(this, EvidenceActivity.class);

        TaskStackBuilder stackBuilder = TaskStackBuilder.create(this);

        // Adds the back stack for the Intent (but not the Intent itself)
        stackBuilder.addParentStack(EvidenceActivity.class);

        // Adds the Intent that starts the Activity to the top of the stack
        stackBuilder.addNextIntent(resultIntent);
        PendingIntent resultPendingIntent =
                stackBuilder.getPendingIntent(0, PendingIntent.FLAG_UPDATE_CURRENT);
        mBuilder.setContentIntent(resultPendingIntent);
        NotificationManager mNotificationManager =
                (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        // mId allows you to update the notification later on.
        mNotificationManager.notify(Const.LOG_TAG, 1, mBuilder.build());
    }

    private void showNoNotification(){
        NotificationManager mNotificationManager =
                (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        mNotificationManager.cancelAll();
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

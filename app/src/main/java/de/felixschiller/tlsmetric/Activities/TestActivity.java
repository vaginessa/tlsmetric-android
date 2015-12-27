package de.felixschiller.tlsmetric.Activities;

import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;
import android.widget.TextView;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

import de.felixschiller.tlsmetric.R;
import de.felixschiller.tlsmetric.modules.CheckDependencies;
import de.felixschiller.tlsmetric.helper.Const;
import de.felixschiller.tlsmetric.modules.PacketProcessing;
import de.felixschiller.tlsmetric.modules.ToolBox;
import de.felixschiller.tlsmetric.modules.VpnBypassService;

public class TestActivity extends AppCompatActivity {

    private ToolBox mTool = new ToolBox();
    private TextView mStatusText;
    public static TestActivity sActivity;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        sActivity = this;
        mTool.initPaths(getApplicationContext());
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_test);
        // Test for Root Acces and Logging
        CheckDependencies checkDependencies = new CheckDependencies();
        checkDependencies.testAll();

        mStatusText = (TextView) findViewById(R.id.testText);
//      mHandler.postDelayed(mUpdateStatusView, 100);

        // start VPN client
        Intent intent = VpnBypassService.prepare(getApplicationContext());
        if (intent != null) {
            startActivityForResult(intent, 0);
        } else {
            onActivityResult(0, RESULT_OK, null);
        }

        Button buttStart = (Button) findViewById(R.id.fabStart);
        buttStart.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (getResources().getBoolean(R.bool.isDebug))
                    Log.d(getResources().getString(R.string.app_name), "Try to start VPN-Service");
                Snackbar.make(view, "Try to start VPN loopback service...", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
                // start VPN client
                Intent intent = VpnBypassService.prepare(getApplicationContext());
                if (intent != null) {
                    startActivityForResult(intent, 0);
                } else {
                    onActivityResult(0, RESULT_OK, null);
                }

            }
        });

        Button buttStop = (Button) findViewById(R.id.fabStop);
        buttStop.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Try to stop VPN-Service");
                Snackbar.make(view, "Try to stop VPN loopback service...", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
                // stop VPN Client
                Intent intent = new Intent(getApplicationContext(), VpnBypassService.class);
                stopService(intent);
            }
        });

        Button startDump = (Button) findViewById(R.id.startDump);
        startDump.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "TCP Metric started.", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
                mTool.deployTcpDump(getApplicationContext());
                //String ifs = mTool.getIfs(getApplicationContext());

                mTool.runTcpDump(getApplicationContext());

            }
        });

        Button stopDump = (Button) findViewById(R.id.stopDump);
        stopDump.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Stop tcpdump");
                mTool.stopTcpDump();
            }
        });

        Button startProcessing = (Button) findViewById(R.id.startProcessing);
        startProcessing.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (Const.IS_DEBUG)
                    Log.d(Const.LOG_TAG, "Do DNS Request!");
                try {
                    Socket socket = new Socket("google.de", 80);
                } catch (IOException e){
                    e.printStackTrace();
                }
            }
        });

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_test, menu);
        return true;
    }


    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }


    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == RESULT_OK) {
            Intent intent = new Intent(this, VpnBypassService.class);
            startService(intent);
        }
    }

}

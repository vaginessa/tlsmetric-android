package de.felixschiller.tlsmetric.Activities;

import android.content.Intent;
import android.os.Bundle;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.Assistant.ContextSingleton;
import de.felixschiller.tlsmetric.Assistant.ToolBox;
import de.felixschiller.tlsmetric.PacketAnalyze.Evidence;
import de.felixschiller.tlsmetric.R;
import de.felixschiller.tlsmetric.RootDump.CheckDependencies;
import de.felixschiller.tlsmetric.RootDump.DumpHandler;
import de.felixschiller.tlsmetric.VpnDump.VpnBypassService;

public class MainActivity extends AppCompatActivity {


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        //Fill the Singleton
        ContextSingleton.setContext(this);

        //TODO: Change Sudo tests
        // Test for Root Acces and Logging
        CheckDependencies.checkSu();

/*
        Button buttStart = (Button) findViewById(R.id.fabStart);
        buttStart.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (Const.IS_DEBUG)Log.d(getResources().getString(R.string.app_name), "Try to start VPN-Service");
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
*/

        Button startDump = (Button) findViewById(R.id.startDump);
        startDump.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Start TLSMetric(Root) Service.", Snackbar.LENGTH_LONG).setAction("Action", null).show();
                DumpHandler.start();
                DumpHandler.startAnalyzerService();
                minimizeActivity();
            }
        });

        Button stopDump = (Button) findViewById(R.id.stopDump);
        stopDump.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Stop TLSMetric(Root) Service", Snackbar.LENGTH_LONG).setAction("Action", null).show();
                DumpHandler.stopAnalyzerService();
                DumpHandler.stop();
            }
        });

        Button gotoEvidence = (Button) findViewById(R.id.gotoEvidence);
        gotoEvidence.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if(ToolBox.isAnalyzerServiceRunning()){
                    Intent intent = new Intent(ContextSingleton.getContext(), EvidenceActivity.class);
                    startActivity(intent);
                } else {
                    Toast toast = Toast.makeText(ContextSingleton.getContext(), "Packet Analyzer Service is not started.", Toast.LENGTH_LONG);
                    toast.show();
                }

            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_tlsmetric, menu);
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

    @Override
    public void onDestroy(){
        //Kill the Singleton
        ContextSingleton.setContext(null);
        super.onDestroy();

    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == RESULT_OK) {
            VpnBypassService.start(this);
        }
    }

    private void minimizeActivity(){
        Intent startMain = new Intent(Intent.ACTION_MAIN);
        startMain.addCategory(Intent.CATEGORY_HOME);
        startMain.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(startMain);
    }

}

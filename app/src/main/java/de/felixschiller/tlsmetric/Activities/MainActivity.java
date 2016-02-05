package de.felixschiller.tlsmetric.Activities;

import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
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
import de.felixschiller.tlsmetric.R;
import de.felixschiller.tlsmetric.RootDump.CheckDependencies;
import de.felixschiller.tlsmetric.RootDump.DumpHandler;
import de.felixschiller.tlsmetric.VpnDump.VpnBypassService;

public class MainActivity extends AppCompatActivity {

    private boolean isRunning;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //Fill the Singleton
        ContextSingleton.setContext(this);

        //TODO: Change Sudo tests
        // Test for Root Acces and Logging
        CheckDependencies.checkSu();

        isRunning = ToolBox.isAnalyzerServiceRunning();

        final Button startStop = (Button) findViewById(R.id.startStop);
        startStop.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                TextView infoText = (TextView) findViewById(R.id.infoText);
                if(!isRunning) {
                    startStop.setBackground(getResources().getDrawable(R.drawable.power_working));
                    isRunning = true;
                    infoText.setText(R.string.info_starting);
                    if(Const.IS_DEBUG) Log.d(Const.LOG_TAG, "begin start sequence.");
                    DumpHandler.start();
                    infoText.setText(R.string.info_waiting);
                    DumpHandler.startAnalyzerService();
                    infoText.setText(R.string.info_running);
                    startStop.setBackground(getResources().getDrawable(R.drawable.power_on));
                    minimizeActivity();
                } else {
                    startStop.setBackground(getResources().getDrawable(R.drawable.power_working));
                    isRunning = false;
                    if(Const.IS_DEBUG) Log.d(Const.LOG_TAG, "begin stop sequence.");
                    infoText.setText(R.string.info_stopping);
                    DumpHandler.stopAnalyzerService();
                    DumpHandler.stop();
                    infoText.setText(R.string.info_handle);
                    startStop.setBackground(getResources().getDrawable(R.drawable.power_off));
                }
            }
        });

        Button gotoEvidence = (Button) findViewById(R.id.gotoEvidence);
        gotoEvidence.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if(isRunning){
                    Intent intent = new Intent(ContextSingleton.getContext(), EvidenceActivity.class);
                    startActivity(intent);
                } else {
                    Toast toast = Toast.makeText(ContextSingleton.getContext(), "TLS Metric service is not yet running.", Toast.LENGTH_LONG);
                    toast.show();
                }

            }
        });


        if(isRunning){
            startStop.setBackground(getResources().getDrawable(R.drawable.power_on));
        } else {
            startStop.setBackground(getResources().getDrawable(R.drawable.power_off));
        }
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

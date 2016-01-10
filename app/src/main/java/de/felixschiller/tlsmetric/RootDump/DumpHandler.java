package de.felixschiller.tlsmetric.RootDump;

import android.widget.Toast;

import com.stericson.RootTools.RootTools;

import de.felixschiller.tlsmetric.Activities.TestActivity;

/**
 * Created by schillef on 10.01.2016.
 */
public class DumpHandler {

    //Checks for su rights
    public void checkSu() {
        if (RootTools.isRootAvailable()) {
            Toast toast = Toast.makeText(TestActivity.sActivity, "Superuser is installed.", Toast.LENGTH_LONG);
            toast.show();
        } else {
            Toast toast = Toast.makeText(TestActivity.sActivity, "Superuser is NOT installed. \n" +
                    "opening download screen", Toast.LENGTH_LONG);
            toast.show();
            //TODO: Does not Work, Why?
            //RootTools.offerSuperUser(TestActivity.sActivity);
        }
    }
}

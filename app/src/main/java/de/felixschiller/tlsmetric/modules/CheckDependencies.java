package de.felixschiller.tlsmetric.modules;

import android.widget.Toast;

import com.stericson.RootTools.RootTools;

import de.felixschiller.tlsmetric.Activities.TestActivity;
import de.felixschiller.tlsmetric.helper.Const;

/**
 * Checks for su and busybox dependecies. These apps are needed for root access based packet dumping.
 */
public class CheckDependencies {


    //If DebugMode is on, do DebugMode on Root Tools
    public void setRootToolsDebug(){
        if(Const.IS_DEBUG){
            RootTools.debugMode = true;
            RootTools.log("Debug == true for RootTools Extension!");
        }
    }
    //Check for Busybox and alert if not found on device
    public void checkBB(){

        if (RootTools.isBusyboxAvailable()) {
            Toast toast = Toast.makeText(TestActivity.sActivity, "BusyBox is installed.", Toast.LENGTH_LONG);
            toast.show();
        } else {
            Toast toast = Toast.makeText(TestActivity.sActivity, "BusyBox is NOT installed. \n" +
                    "opening download screen", Toast.LENGTH_LONG);
            toast.show();
            //TODO: Does not Work, Why?
            //RootTools.offerBusyBox(TestActivity.this);
        }
    }
    //Check for su and alert if not found on device
    public void checkSu(){

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
    // Tests for all Methods
    public void testAll(){
       setRootToolsDebug();
        checkSu();
        checkBB();
    }

}

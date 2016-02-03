package de.felixschiller.tlsmetric.RootDump;

import android.widget.Toast;

import com.stericson.RootTools.RootTools;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.Assistant.ContextSingleton;

/**
 * Checks for su and busybox dependecies. These apps are needed for root access based packet dumping.
 */
public class CheckDependencies {


    //Check for su and alert if not found on device
    public static void checkSu(){

        if (RootTools.isRootAvailable()) {
            Toast toast = Toast.makeText(ContextSingleton.getActivity(), "Superuser is installed.", Toast.LENGTH_LONG);
            toast.show();
        } else {
            Toast toast = Toast.makeText(ContextSingleton.getActivity(), "Superuser is NOT installed. \n" +
                    "opening download screen", Toast.LENGTH_LONG);
            toast.show();
            //TODO: Does not Work, Why?
            //RootTools.offerSuperUser(MainActivity.sActivity);
        }
    }


}

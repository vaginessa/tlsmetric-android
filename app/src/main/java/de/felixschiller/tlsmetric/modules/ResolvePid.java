package de.felixschiller.tlsmetric.modules;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.pm.PackageManager;

import java.util.Iterator;
import java.util.List;

/**
 * Created by schillef on 17.11.15.
 */
public class ResolvePid {

/*    private String[] getPackageNames(int pid) {
        ActivityManager activityManager = (ActivityManager)getContext().getSystemService(Activity.ACTIVITY_SERVICE);
        List<ActivityManager.RunningAppProcessInfo> runningAppProcesses = activityManager.getRunningAppProcesses();
        for (ActivityManager.RunningAppProcessInfo runningAppProcessInfo : runningAppProcesses) {
            try {
                if (runningAppProcessInfo.pid == pid) {
                    return runningAppProcessInfo.pkgList;
                }
            } catch (Exception e) {
            }
        }
        return null;
    }

    private String getAppName(int pID) {
        String processName = "";
        ActivityManager am = (ActivityManager) this.getSystemService(ACTIVITY_SERVICE);
        List l = am.getRunningAppProcesses();
        Iterator i = l.iterator();
        PackageManager pm = this.getPackageManager();
        while (i.hasNext()) {
            ActivityManager.RunningAppProcessInfo info = (ActivityManager.RunningAppProcessInfo) (i.next());
            try {
                if (info.pid == pID) {
                    CharSequence c = pm.getApplicationLabel(pm.getApplicationInfo(info.processName, PackageManager.GET_META_DATA));
                    //Log.d("Process", "Id: "+ info.pid +" ProcessName: "+ info.processName +"  Label: "+c.toString());
                    //processName = c.toString();
                    processName = info.processName;
                }
            } catch (Exception e) {
                //Log.d("Process", "Error>> :"+ e.toString());
            }
        }
        return processName;
    }*/
}
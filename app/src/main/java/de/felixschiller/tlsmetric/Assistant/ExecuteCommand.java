package de.felixschiller.tlsmetric.Assistant;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;

/*
 * Handles the execution of shell commands.
 */
public class ExecuteCommand extends Thread {

    //Execute user commands.
    public static void user(String string) {
        if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Executing as user: " + string);
        try {
            Process user = Runtime.getRuntime().exec(string);
            try {
                user.waitFor();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //Execute user commands and get the result.
    public static String userForResult(String string) {
        //if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Executing for result as user: " + string);
        String res = "";
        DataOutputStream outputStream = null;
        InputStream response = null;
        try {
            Process user = Runtime.getRuntime().exec(string);

            outputStream = new DataOutputStream(user.getOutputStream());
            response = user.getInputStream();

            outputStream.writeBytes("exit\n");
            outputStream.flush();
            try {
                user.waitFor();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            res = readFully(response);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            closeSilently(outputStream, response);
        }
        return res;
    }

    //Execute a command as superuser. Test for su binary present required.
    public static void sudo(String... strings) {

        try {
            Process su = Runtime.getRuntime().exec("su");
            DataOutputStream outputStream = new DataOutputStream(su.getOutputStream());

            for (String s : strings) {
                if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Executing as SU: " + s);
                outputStream.writeBytes(s + "\n");
                outputStream.flush();
            }

            outputStream.writeBytes("exit\n");
            outputStream.flush();
            try {
                su.waitFor();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            outputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //Execute a command as superuser and get the command output. Test for su binary present required.
    public static String sudoForResult(String... strings) {
        String res = "";
        DataOutputStream outputStream = null;
        InputStream response = null;
        try {
            Process su = Runtime.getRuntime().exec("su");

            outputStream = new DataOutputStream(su.getOutputStream());
            response = su.getInputStream();

            for (String s : strings) {
                if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Executing as SU: " + s);
                outputStream.writeBytes(s + "\n");
                outputStream.flush();
            }

            outputStream.writeBytes("exit\n");
            outputStream.flush();
            try {
                su.waitFor();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            res = readFully(response);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            closeSilently(outputStream, response);
        }
        return res;
    }

    //Read the command output and return an utf8 string.
    public static String readFully(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length = 0;
        while ((length = is.read(buffer)) != -1) {
            baos.write(buffer, 0, length);
        }
        return baos.toString("UTF-8");
    }

    //Closes a variety of closable objects.
    public static void closeSilently(Object... xs) {
        // Note: on Android API levels prior to 19 Socket does not implement Closeable
        for (Object x : xs) {
            if (x != null) {
                try {
                    if (x instanceof Closeable) {
                        ((Closeable) x).close();
                    } else {
                        Log.d(Const.LOG_TAG, "cannot close: " + x);
                        throw new RuntimeException("cannot close " + x);
                    }
                } catch (Throwable e) {
                    e.printStackTrace();
                }
            }
        }
    }
}

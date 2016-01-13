package de.felixschiller.tlsmetric.Assistant;


import android.app.Activity;
import android.content.Context;

public class ContextSingleton {

        private static Activity gContext;

        public static void setContext( Activity activity) {
            gContext = activity;
        }

        public static Activity getActivity() {
            return gContext;
        }

        public static Context getContext() {
            return gContext;
        }
}

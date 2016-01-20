package de.felixschiller.tlsmetric.PacketAnalyze;


import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.ListIterator;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.Assistant.ContextSingleton;
import de.felixschiller.tlsmetric.Assistant.ExecuteCommand;
import de.felixschiller.tlsmetric.Assistant.ToolBox;
import de.felixschiller.tlsmetric.R;

/**
 * Holds filters for accessing from packet analyzer and can parses them from a given file.
 */
public class FilterRules {
    private static ArrayList<Filter> mFilterList = new ArrayList<>();

    public FilterRules() {
        deployFilterFile(ContextSingleton.getContext());
        parseFilterList(new File(ContextSingleton.getContext().getFilesDir(), Const.FILE_FILTER));
        if (Const.IS_DEBUG) {
            debugPrintFilterRules();
        }
    }

    public static ArrayList<Filter> getFilterList(){
        return mFilterList;
    }

    private static void addFilter(Filter filter) {
        mFilterList.add(filter);
    }

    private static void parseFilterList(File file){
        String statement;

        try{
            FileReader fr = new FileReader(file);
            BufferedReader br = new BufferedReader(fr);

            while((statement = br.readLine()) != null){
                if(!statement.substring(0,1).equals("#")){
                    generateFilter(statement);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private static void generateFilter(String statement) {
        char separator = ",".toCharArray()[0];
        int current = 0;
        int position = 0;

        String protocol = null;
        String severity = null;
        String description = null;
        String value = null;

        if(statement.contains("IS_PRESENT")){
            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Building IS_PRESENT filter rule.");
            for(int i = 0; i < statement.length(); i++ ){
                if(statement.charAt(i) == separator){
                    current++;
                    String result = statement.substring(position, i);
                    position = i + 1;
                    if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Found: " + result);
                    switch (current)
                    {
                        case 1:
                            break;
                        case 2:
                        protocol = result;
                            break;
                        case 3:
                        severity = result;
                            break;
                        case 4:
                            description = result;
                            break;
                        default:
                            break;
                    }
                }
            }
            addFilter(new Filter(Filter.FilterType.IS_PRESENT, protocol, (short)(severity.charAt(0)), description));
        }

        if(statement.contains("CONTAINS")){
            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Building CONTAINS filter rule.");
            for(int i = 0; i < statement.length(); i++ ){
                if(statement.charAt(i) == separator){
                    current++;
                    String result = statement.substring(position, i);
                    position = i + 1;
                    if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Found: " + result);
                    switch (current)
                    {
                        case 1:
                            break;
                        case 2:
                            protocol = result;
                            break;
                        case 3:
                            severity = result;
                            break;
                        case 4:
                            value = result;
                            break;
                        case 5:
                            description = result;
                            break;

                        default:
                            break;
                    }
                }
            }
            try {
                addFilter(new Filter(Filter.FilterType.CONTAINS, protocol, ToolBox.hexStringToByteArray(value), (short) (severity.charAt(0)), description));
            } catch (NumberFormatException e) {
                Log.e(Const.LOG_TAG, "Invalid filter rule detected: " + statement + " \n -- Check for invalid HexString: " + value);
                e.printStackTrace();
            }
        }
    }

    //Extract the filter file to /system/bin folder
    public void deployFilterFile(Context context) {
        File file = new File(context.getFilesDir(), Const.FILE_FILTER);
        try {
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Extract filter.ini");
            InputStream in = context.getResources().openRawResource(R.raw.filter);
            byte[] buffer = new byte[in.available()];
            in.read(buffer);
            OutputStream out = new FileOutputStream(file);
            out.write(buffer);
        } catch (Exception e) {
            Log.e(Const.LOG_TAG, "Deserialization of " + Const.FILE_FILTER + " failed", e);
        }
        ExecuteCommand.user("chmod 6755 " + file.getAbsolutePath());
    }

    public void debugPrintFilterRules() {
        Log.i(Const.LOG_TAG, mFilterList.size() + " Filters in current ruleset.");
        if (Const.IS_DEBUG) {
            ListIterator ite = mFilterList.listIterator();
            while (ite.hasNext()) {
                Filter filter = (Filter) ite.next();
                Log.d(Const.LOG_TAG, filter.getSummary());
            }
        }
    }
}

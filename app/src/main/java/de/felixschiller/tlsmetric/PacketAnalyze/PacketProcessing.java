package de.felixschiller.tlsmetric.PacketAnalyze;

import android.util.Log;

import com.voytechs.jnetstream.codec.Packet;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.ListIterator;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.Assistant.ToolBox;

/**
 * Created by schillef on 20.01.16.
 */
public class PacketProcessing {
    private ArrayList<Filter> mFilterList;

    public PacketProcessing(){
        FilterRules filterGenerator = new FilterRules();
        mFilterList = filterGenerator.getFilterList();
    }

    public void processPacket(Packet pkt){
        ListIterator ite = mFilterList.listIterator();
        ArrayList<Filter> foundList = new ArrayList<>();
        while (ite.hasNext()){
            Filter filter = (Filter)ite.next();
            if(processFilter(pkt, filter)){
                foundList.add(filter);
            }
        }

        //TODO: Change from debug to productive
        if (foundList.isEmpty()){
            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "No filters triggered.");
        } else {
            String debug = "";
            ite = foundList.listIterator();
            while(ite.hasNext()){
                Filter filter = (Filter)ite.next();
                debug.concat(filter.description + ", ");
            }
        }
    }

    private boolean processFilter(Packet pkt, Filter filter) {

        switch (filter.filterType){

            case IS_PRESENT:
                if(pkt.hasHeader(filter.protocol)){
                    if(Const.IS_DEBUG) Log.d(Const.LOG_TAG, filter.protocol + " protocol found.");
                    return true;
                } else {
                    return false;
                }

            case CONTAINS :
                if(pkt.hasHeader(filter.protocol)){
                    if(Const.IS_DEBUG) Log.d(Const.LOG_TAG, filter.protocol + " protocol found.");
                    byte[] b = pkt.getDataValue();
                    if(Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Search for " + ToolBox.printHexBinary(filter.value) + " in " + ToolBox.printHexBinary(b));
                    int atPos = searchByteArray(b, filter.value);
                    if (atPos != -1){
                        if(Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Found " + ToolBox.printHexBinary(filter.value) + " at position " + atPos);
                        return true;
                    }
                } else {
                    return false;
                }

            default:
                return false;
        }
    }


    public static int searchByteArray(byte[] input, byte[] searchedFor) {
        //convert byte[] to Byte[]
        Byte[] searchedForB = new Byte[searchedFor.length];
        for(int x = 0; x<searchedFor.length; x++){
            searchedForB[x] = searchedFor[x];
        }

        int idx = -1;
        //search:
        Deque<Byte> q = new ArrayDeque<Byte>(input.length);
        for(int i=0; i<input.length; i++){
            if(q.size() == searchedForB.length){
                //here I can check
                Byte[] cur = q.toArray(new Byte[]{});
                if(Arrays.equals(cur, searchedForB)){
                    //found!
                    idx = i - searchedForB.length;
                    break;
                } else {
                    //not found
                    q.pop();
                    q.addLast(input[i]);
                }
            } else {
                q.addLast(input[i]);
            }
        }
        return idx;
    }
}

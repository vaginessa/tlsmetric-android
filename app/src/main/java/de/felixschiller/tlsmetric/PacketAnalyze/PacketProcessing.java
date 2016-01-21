package de.felixschiller.tlsmetric.PacketAnalyze;

import android.util.Log;

import com.voytechs.jnetstream.codec.Packet;

import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.ListIterator;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Filter;
import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Identifyer;
import de.felixschiller.tlsmetric.VpnDump.ConnectionHandler;

/**
 * Created by schillef on 20.01.16.
 */
public class PacketProcessing {
    private ArrayList<Filter> mFilterList;

    public PacketProcessing(){

    }

    public static int searchByteArray(byte[] input, byte[] searchedFor) {
        //convert byte[] to Byte[]
        Byte[] searchedForB = new Byte[searchedFor.length];
        for (int x = 0; x < searchedFor.length; x++) {
            searchedForB[x] = searchedFor[x];
        }

        int idx = -1;
        //search:
        Deque<Byte> q = new ArrayDeque<>(input.length);
        for (int i = 0; i < input.length; i++) {
            if (q.size() == searchedForB.length) {
                //here I can check
                Byte[] cur = q.toArray(new Byte[]{});
                if (Arrays.equals(cur, searchedForB)) {
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

    public void processPacket(Packet pkt) {
        ListIterator ite = mFilterList.listIterator();
        ArrayList<Filter> foundList = new ArrayList<>();
        while (ite.hasNext()) {
            Filter filter = (Filter) ite.next();

        }

        //TODO: Change from debug to productive
        if (foundList.isEmpty()) {
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "No filters triggered.");
        } else {
            String debug = "";
            ite = foundList.listIterator();
            while (ite.hasNext()) {
                Filter filter = (Filter) ite.next();
                debug = debug.concat(filter.description + ", ");
            }
        }
    }

    private Filter scanPacket(Packet pkt) {

        if (pkt.hasHeader("TCP")) {
            byte[] b = pkt.getDataValue();
            int offset = ConnectionHandler.getHeaderOffset(pkt);
            Log.e(Const.LOG_TAG, "Offset: " + offset);
            ByteBuffer bb = ByteBuffer.allocate(b.length - offset);
            bb.put(b, offset, b.length - offset);

            byte[] ident = new byte[4];
            bb.position(0);
            bb.get(ident);
            return Identifyer.indent(ident);
        } else {
            return null;
        }
    }
}

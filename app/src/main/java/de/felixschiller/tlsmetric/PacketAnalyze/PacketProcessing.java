package de.felixschiller.tlsmetric.PacketAnalyze;

import android.util.Log;

import com.voytechs.jnetstream.codec.Packet;

import java.nio.ByteBuffer;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Filter;
import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Identifyer;

/**
 * Created by schillef on 20.01.16.
 */
public class PacketProcessing {

    public void processPacket(Packet pkt) {
        Filter filter = scanPacket(pkt);
        if (filter != null) {
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Filter triggered: " + filter.protocol);
        }

    }

    private Filter scanPacket(Packet pkt) {

        if (pkt.hasHeader("TCP") && pkt.hasDataHeader()) {
            byte[] b = pkt.getDataValue();
            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, b.length + " Bytes data found");
            ByteBuffer bb = ByteBuffer.allocate(b.length);
            bb.put(b);


            byte[] ident = new byte[8];
            bb.position(0);
            bb.get(ident);
            return Identifyer.indent(ident);
        } else {
            return null;
        }
    }
}

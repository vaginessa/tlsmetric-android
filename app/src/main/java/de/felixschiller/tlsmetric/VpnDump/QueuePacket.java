package de.felixschiller.tlsmetric.VpnDump;

import com.voytechs.jnetstream.codec.Packet;

import java.nio.channels.SelectionKey;

/**
 * Created by schillef on 22.12.15.
 */
public class QueuePacket {
    public SelectionKey key;
    public Packet pkt;
    public byte[] b;
    public QueuePacket(SelectionKey key, byte[] b, Packet pkt){
        this.key = key;
        this.b = b;
        this.pkt = pkt;
    }
}

package de.felixschiller.tlsmetric.helper;

import java.nio.channels.SelectionKey;

/**
 * Created by schillef on 22.12.15.
 */
public class QueuePacket {
    public SelectionKey key;
    public byte[] b;
    public QueuePacket(SelectionKey key, byte[] b){
        this.key = key;
        this.b = b;
    }
}

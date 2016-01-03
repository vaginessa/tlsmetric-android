package de.felixschiller.tlsmetric.helper;

import java.sql.Timestamp;
import java.util.LinkedList;
import java.util.Queue;

/**
 * Extended socket data  class with flags and sequence numbers to keep track of tcp flows.
 */
public class TcpFlow extends SocketData{
    /*Caution: Some flags are ignored, since this implementation has no control of all tcp
     * mechanisms.
    */
    public byte[] flags;
    public byte[] seqNr;
    public byte[] ackNr;

    public boolean syn;
    public boolean fin;
    public boolean rst;

    public boolean isBreakdown;

    public Queue<byte[]> seqQueue = new LinkedList<>();
    public Queue<byte[]> ackQueue = new LinkedList<>();

    public TcpFlow(byte[] srcAdd, byte[] dstAdd, int srcPort, int dstPort, Timestamp time, int ipVersion) {
        super(srcAdd, dstAdd, srcPort, dstPort,time, ipVersion);
        super.setTransport(Transport.TCP);
    }


}

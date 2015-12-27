package de.felixschiller.tlsmetric.helper;


import java.sql.Timestamp;

/**
 * UdpFlow Dummy
 */
public class UdpFlow extends SocketData{

    public UdpFlow(byte[] srcAdd, byte[] dstAdd, int srcPort, int dstPort, Timestamp time, int ipVersion){
        super(srcAdd, dstAdd, srcPort,dstPort,time, ipVersion);
        super.setTransport(Transport.UDP);
    }
}

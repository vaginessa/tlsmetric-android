package de.felixschiller.tlsmetric.modules;

import android.util.Log;

import com.voytechs.jnetstream.codec.Header;
import com.voytechs.jnetstream.codec.Packet;
import com.voytechs.jnetstream.primitive.address.Address;

import java.sql.Timestamp;

import de.felixschiller.tlsmetric.helper.SocketData;
import de.felixschiller.tlsmetric.helper.TcpFlow;
import de.felixschiller.tlsmetric.helper.UdpFlow;

/**
 * Created by schillef on 21.12.15.
 */
public class ConnectionHandler {


    /*
     * Extracts the necessary ISO/OSI layer3/layer4 header data for the connection flow. Existence
     * of an IP-Header has to be already confirmed.
     */
    public static SocketData extractFlowData(Packet pkt) {
        Header ipHeader;
        Header transportHeader;
        int version;
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        SocketData flow;

        //Read IP and transport Header
        if (pkt.hasHeader("IPv4")) {
            ipHeader = pkt.getHeader("IPv4");
            version = 4;
        } else if (pkt.hasHeader("IPv6")){
            ipHeader = pkt.getHeader("IPv6");
            version = 6;
        } else {
            ipHeader = null;
            version = -1;
        }

        if (pkt.hasHeader("TCP") && ipHeader != null) {
            transportHeader = pkt.getHeader("TCP");
            flow = new TcpFlow(new byte[]{}, new byte[]{},0, 0, timestamp, version);
            flow.offset = (int) ipHeader.getValue("hlen") * 4 + (int)transportHeader.getValue("hlen") * 4;
        }else if (pkt.hasHeader("UDP") && ipHeader != null ) {
            transportHeader = pkt.getHeader("UDP");
            flow = new UdpFlow(new byte[]{}, new byte[]{},0, 0, timestamp, version);
            flow.offset = (int) ipHeader.getValue("hlen") * 4 + 8;
        } else {
            transportHeader = null;
            flow = null;
        }

        if(flow != null) {
            //Get ports and addresses from header
            Address address = (Address)ipHeader.getValue("daddr");
            flow.setDstAdd(address.toByteArray());
            address = (Address)ipHeader.getValue("saddr");
            flow.setSrcAdd(address.toByteArray());
            flow.setDstPort((int) transportHeader.getValue("dport"));
            flow.setSrcPort((int) transportHeader.getValue("sport"));

        }
        return flow;
    }

    public static int getHeaderOffset(Packet pkt){
        Header ipHeader;
        Header transportHeader;

        //Read IP and transport Header
        if (pkt.hasHeader("IPv4")) {
            ipHeader = pkt.getHeader("IPv4");
        } else if (pkt.hasHeader("IPv6")){
            ipHeader = pkt.getHeader("IPv6");
        } else {
            ipHeader = null;
        }

        if (pkt.hasHeader("TCP") && ipHeader != null) {
            transportHeader = pkt.getHeader("TCP");
            return (int) ipHeader.getValue("hlen") * 4 + (int)transportHeader.getValue("hlen") * 4;
        }else if (pkt.hasHeader("UDP") && ipHeader != null ) {
            return (int) ipHeader.getValue("hlen") * 4 + 8;
        } else {
            return -1;
        }

    }

}

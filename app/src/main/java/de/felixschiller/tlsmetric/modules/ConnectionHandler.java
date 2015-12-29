package de.felixschiller.tlsmetric.modules;

import android.util.Log;

import com.voytechs.jnetstream.codec.Header;
import com.voytechs.jnetstream.codec.Packet;
import com.voytechs.jnetstream.primitive.address.Address;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.sql.Timestamp;
import java.util.Iterator;
import java.util.Set;

import de.felixschiller.tlsmetric.helper.Const;
import de.felixschiller.tlsmetric.helper.PacketGenerator;
import de.felixschiller.tlsmetric.helper.SocketData;
import de.felixschiller.tlsmetric.helper.TcpFlow;
import de.felixschiller.tlsmetric.helper.UdpFlow;

/**
 * Connection Handler.. what more to say
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

    public static void closeConnection(int id) throws IOException {
        Set<SelectionKey> allKeys = VpnBypassService.mSelector.keys();
        Iterator<SelectionKey> keyIterator = allKeys.iterator();
        SelectionKey key;
        while (keyIterator.hasNext()) {
            key = keyIterator.next();
            SocketData data = (SocketData) key.attachment();
            if (data.getSrcPort() == id) {
                if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "closing Channel ID = " + id);
                key.channel().close();
                key.cancel();
            }
        }
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

    /*
     * Kills channels if expired or void
     */
    public static void garbageChannels(Packet pkt) throws IOException {

        // Kill UDP channels by timeout or DNS answer
        //TODO: generate logic and stuff
        if(pkt.hasHeader("UDP")){
            int id = (int)pkt.getHeader("UDP").getValue("dport");
            closeConnection(id);
        }
    }

    /*
     * Kills all artificial VPN Bypass channels
     */
    public static void killAll() throws IOException {
        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Closing ALL channels.");
        Set<SelectionKey> allKeys = VpnBypassService.mSelector.keys();
        Iterator<SelectionKey> keyIterator = allKeys.iterator();
        SelectionKey key;
        while (keyIterator.hasNext()) {
            key = keyIterator.next();
            key.channel().close();
            key.cancel();
        }
    }

    public static byte[] handleFlags(TcpFlow flow) throws IOException {

        //Detect SYN Flag and initiate Handshake if present
        if (flow.syn && !flow.isOpen) {
            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "SYN Flag detected, initiating Handshake.");
            return PacketGenerator.forgeHandshake(flow);
        }

        //Detect Rst flag and Handle
        if (flow.rst) {
            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "FIN Flag detected, initiating closing sequence.");
            closeConnection(flow.getSrcPort());
            //TODO: sent rst ack packet, close channel
            return null;
        }

        //Detect Rst flag and close/unregister from Selector
        if (flow.fin) {
            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "FIN Flag detected, initiating closing sequence.");
            closeConnection(flow.getSrcPort());
            //TODO: sent fin ack packet
            return null;
        }
        return null;
    }
}

package de.felixschiller.tlsmetric.helper;

import android.util.Log;

import com.voytechs.jnetstream.codec.Header;

import org.jnetpcap.protocol.network.Ip4;

import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.sql.Timestamp;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;

import de.felixschiller.tlsmetric.modules.ConnectionHandler;
import de.felixschiller.tlsmetric.modules.ToolBox;
import de.felixschiller.tlsmetric.modules.VpnBypassService;

/**
 * Generates Answering Packages
 */
public class PacketGenerator {

    /* Protocol Byte information below:
     * #############################################################################################
     * ##  IP4
     * #############################################################################################
     * Byte : Information
     * 1    : Version(4Bit) + Header Length(4Bit)
     * 2    : TOS
     * 3-4  : TotalLength
     * 5-6  : Identification
     * 7-8  : Flags(3 Bit: reserved - DF: Don't Fragment - MF: More Fragments+(13 Bit)FragmentOffset
     * 9    : TTL
     * 10   : Carrying protocol(17(0x11) = UDP, 6(0x06) = TCP)
     * 11-12: HeaderChecksum
     * 13-16: SrcAddress
     * 17-20: DstAddress
     * 21-40: Options, See RFC 791 - https://tools.ietf.org/html/rfc791 -- ignored.
     *
     * #############################################################################################
     * ##   IP6
     * #############################################################################################
     *
     * Not yet implemented.
     *
     * #############################################################################################
     * ##   UDP
     * #############################################################################################
     * Byte : Information
     * 1-2  : Source Port
     * 3-4  : Destination Port
     * 5-6  : Length of UDP Header(8) + Payload in Bytes
     * 7-8  : Checksum (or Zero) -- Note needed internally and hence ignored.
     *
     * #############################################################################################
     * ##   TCP
     * #############################################################################################
     * Byte : Information
     * 1-2  : Source Port
     * 3-4  : Destination Port
     * 5-8  : Sequence Number
     * 9-12 : Acknowledge Number
     * 13   : Header Length (Bit 0-3 * 4 Bytes, like IP), (Bit 4-7 reserved and nonce Bit)
     * 14   : Flags (CWR, ECN, URG, ACK, PSH, RST, SYN, FIN)
     * 15-16: Window Size (value * scaling factor 256)
     * 17-18: Checksum
     * 19-20: Urgent Pointer (offset)
     * 21-40: Options (if defined in header length - ignored)
     * #############################################################################################
    */
    private static final byte[] sIp4Dummy = hexStringToByteArray("45000086001100003d1100001111111122222222");
    private static final byte[] sIp6Dummy = hexStringToByteArray("");
    private static final byte[] sTcpDummy = hexStringToByteArray("111122221111111122222222501005ac00000000");
    private static final byte[] sUdpDummy = hexStringToByteArray("111122220072fc42");

    //Generates packets based on stored connection data.
    public static byte[] generatePacket(SocketData data, byte[] b){
        if(data.getIpVersion() == 4){
            if(data.getTransport() == SocketData.Transport.TCP){
                //Generate a ip(tcp(payload)) packet with connection data and checksum
                int length = sIp4Dummy.length + sTcpDummy.length + b.length;
                ByteBuffer bb = ByteBuffer.allocate(length);
                byte[] ipPayload = forgeTCP((TcpFlow)data, b);
                bb.put(forgeIp4(data, ipPayload));
                return bb.array();
            }
            else if(data.getTransport() == SocketData.Transport.UDP){
                //Generate a ip(udp(payload)) packet with connection data and checksum
                int length = sIp4Dummy.length + sUdpDummy.length + b.length;
                ByteBuffer bb = ByteBuffer.allocate(length);
                byte[] ipPayload = forgeUDP(data, b);
                bb.put(forgeIp4(data, ipPayload));
                return bb.array();
            }
        }
        else if(data.getIpVersion() == 6) {
            if(data.getTransport() == SocketData.Transport.TCP){
                //Generate a ip(tcp(payload)) packet with connection data and checksum
                int length = sIp6Dummy.length + sTcpDummy.length + b.length;
                ByteBuffer bb = ByteBuffer.allocate(length);
                bb.put(sIp6Dummy);
                bb.put(sTcpDummy);
                bb.put(b);

                return bb.array();
            }
            else if(data.getTransport() == SocketData.Transport.UDP){
                //Generate a ip(udp(payload)) packet with connection data and checksum
                int length = sIp6Dummy.length + sUdpDummy.length + b.length;
                ByteBuffer bb = ByteBuffer.allocate(length);
                byte[] ipPayload = forgeUDP(data, b);
                bb.put(forgeIp4(data, ipPayload));
                return bb.array();
            }
        }
        return b;
    }

    public static byte[] forgeIp4(SocketData data, byte[] payload){
        int length =  sIp4Dummy.length + payload.length;
        //ByteBuffers for assembling and int-conversion.
        ByteBuffer bb = ByteBuffer.allocate(length);
        ByteBuffer bint = ByteBuffer.allocate(4);
        bb.put(sIp4Dummy);
        bb.put(payload);
        //fill packet length
        bb.position(2);
        bint.position(0);
        bint.putInt(length);
        bb.put(bint.array(), 2, 2);
        //Identification Field needed?
        //fill protocol
        bb.position(9);
        if(data.getTransport() == SocketData.Transport.UDP){
            bb.put((byte)17);
        } else{
            bb.put((byte)6);
        }
        //Add source and destination address
        bb.position(12);
        bb.put(data.getDstAdd());
        bb.put(data.getSrcAdd());

        //Last but not least: generate checksum
        bb.position(0);
        byte[] v4header = new byte[20];
        bb.get(v4header);
        byte[] cs = longToFourBytes(computeChecksum(v4header));
        bb.position(10);
        bb.put(cs, 2, 2);
        return bb.array();
    }
    public static byte[] forgeIp6(SocketData data, byte[] payload){
        //TODO: implement
        return null;
    }
    public static byte[] forgeTCP(TcpFlow data, byte[] payload){
        int length =  sTcpDummy.length + payload.length;
        //ByteBuffers for assembling and int-conversion.
        ByteBuffer bb = ByteBuffer.allocate(length);
        ByteBuffer bint = ByteBuffer.allocate(4);
        bb.put(sTcpDummy);
        bb.put(payload);
        bb.position(0);
        //fill source and destination ports
        bint.putInt(data.getDstPort());
        bb.put(bint.array(), 2, 2);
        bint.position(0);
        bint.putInt(data.getSrcPort());
        bb.put(bint.array(), 2, 2);

        //Manage AckNumber
        if(!data.ackQueue.isEmpty()){
            data.ackNr = data.ackQueue.poll();
        }
        if(!data.seqQueue.isEmpty()){
            data.seqNr = data.seqQueue.poll();
        }
        bb.put(data.seqNr);
        //insert ack number (calculated in send method)
        bb.put(data.ackNr);

        //increment seq Number if need be and add to queue
        long inc = fourBytesToLong(tcpIncrementer(data.ackNr, payload.length));
        if(!(inc == fourBytesToLong(data.seqNr))){
         data.seqQueue.add(longToFourBytes(inc));

        }
        //Flags for ACK are set in dummy
        //Checksum generation
        byte[] pseudoHeader = generatePseudoHeader(data, bb.array());
        byte[] cs = longToFourBytes(computeChecksum(pseudoHeader)-2);
            bb.position(16);
            bb.put(cs, 2, 2);
        return bb.array();
    }


    //Forge an udp packet based on the dummy
    public static byte[] forgeUDP(SocketData data, byte[] payload){
        int length =  sUdpDummy.length + payload.length;
        //ByteBuffers for assembling and int-conversion.
        ByteBuffer bb = ByteBuffer.allocate(length);
        ByteBuffer bint = ByteBuffer.allocate(4);
        bb.put(sUdpDummy);
        bb.put(payload);
        bb.position(0);
        //fill source and destination ports
        bint.putInt(data.getDstPort());
        bb.put(bint.array(), 2, 2);
        bint.position(0);
        bint.putInt(data.getSrcPort());
        bb.put(bint.array(), 2, 2);
        //fill packet length
        bint.position(0);
        bint.putInt(length);
        bb.put(bint.array(), 2, 2);
        //fill checksum with 0 no Checksum used
        bint.position(0);
        bint.putInt(0);
        bb.put(bint.array(), 2, 2);
        return bb.array();
    }

    public static byte[] hexStringToByteArray(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    /*
     * TCP flow control and packet forging logic methods for transmitting packages.
     */
    public static void handleFlowAtSend(TcpFlow data, Header header, int payloadLen){
        if (data.seqNr == null) {
            data.seqNr = longToFourBytes((long) header.getValue("seq"));
        }
        if (data.ackNr == null) {
            data.ackNr = longToFourBytes((long) header.getValue("seq"));
        }
        data.flags = intToTwoBytes((int) header.getValue("code"));
        data.fin = ((data.flags[1] & (byte) 0x01) != (byte) 0x00);
        data.syn = ((data.flags[1] & (byte) 0x02) != (byte) 0x00);
        data.rst = ((data.flags[1] & (byte) 0x04) != (byte) 0x00);
        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Handle Flow of channel id: " + data.getSrcPort()
                + ", seq: " + header.getValue("seq") + ". Flags: fin " + data.fin + " syn " + data.syn + " rst "
                + data.rst + " payload length: " + payloadLen);

        long inc = fourBytesToLong(tcpIncrementer(longToFourBytes((long)header.getValue("seq")), payloadLen));
        if(!(inc == fourBytesToLong(data.ackNr))){
            data.ackQueue.add(longToFourBytes(inc));
        }
    }
    /*
     * TCP flow control and packet forging logic methods called after receiving packages.
     */
    public static void handleFlowAtRecieve(TcpFlow data, Header header, int payloadLen){
        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Handle receiving Flow");

        long inc = fourBytesToLong(tcpIncrementer(data.seqNr, payloadLen));
        if(!(inc == fourBytesToLong(data.seqNr))){
            data.seqQueue.add(tcpIncrementer(longToFourBytes((long) header.getValue("seq")), payloadLen));
        }
    }

    public static byte[] forgeHandshake(TcpFlow flow){

        //Clear ack and seq queues
        flow.ackQueue = new LinkedList<>();
        flow.seqQueue = new LinkedList<>();

        //Increment Ack + 1 and generate Answer
        flow.ackNr = tcpIncrementer(flow.ackNr, 1);
        byte[] synAck = generatePacket(flow, new byte[]{});
        //create syn/ack flag
        synAck[33] = (byte)0x12;
        //Increment Seq + 1 and set Ignore Next Packet
        flow.seqNr = tcpIncrementer(flow.seqNr, 1);
        //Set the flow to handshake completed
        flow.isOpen = true;
        return synAck;
    }

    public static byte[] forgeBreakdown(TcpFlow flow){

        //Clear ack and seq queues
        flow.ackQueue = new LinkedList<>();
        flow.seqQueue = new LinkedList<>();

        if(flow.flags[0] == (byte)0x11){
            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG,"ACK_FIN detected");
            //Increment Ack = SYN + 1; SYN = ACK and generate Answer
            byte[] seq = flow.ackNr;
            flow.ackNr = tcpIncrementer(flow.seqNr, 1);
            flow.seqNr = seq;
            byte[] fin = generatePacket(flow, new byte[]{});
            //create FIN flag
            fin[33] = (byte)0x10;
            flow.isOpen = false;
            return fin;
        }

        if(flow.flags[0] == (byte)0x11){
            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG,"FIN detected");
            //Increment Ack = SYN + 1; SYN = ACK and generate Answer
            byte[] seq = flow.ackNr;
            flow.ackNr = tcpIncrementer(flow.seqNr, 1);
            flow.seqNr = seq;
            byte[] fin = generatePacket(flow, new byte[]{});
            //create FIN flag
            fin[33] = (byte)0x01;
            flow.isOpen = false;
            return fin;
        }

        return null;
    }

    public static byte[] tcpIncrementer(byte[] number, int offset) {
        //ByteBuffer to convert the Int-s
        ByteBuffer bb = ByteBuffer.allocate(8);
        bb.position(4);
        bb.put(number);
        bb.position(0);
        long num = bb.getLong();
        if (num + offset > Long.MAX_VALUE){
            num = (num + offset)%Long.MAX_VALUE;
            return longToFourBytes(num);
        } else{
            return longToFourBytes(num+offset);
        }
    }

    /*
     * Calculate the Internet Checksum of a buffer (RFC 1071 - http://www.faqs.org/rfcs/rfc1071.html)
     * Algorithm is
     * 1) apply a 16-bit 1's complement sum over all octets (adjacent 8-bit pairs [A,B], final odd length is [A,0])
     * 2) apply 1's complement to this final sum
     *
     * Notes:
     * 1's complement is bitwise NOT of positive value.
     * Ensure that any carry bits are added back to avoid off-by-one errors
     */
    public static long computeChecksum(byte[] buf) {
        int length = buf.length;
        int i = 0;

        long sum = 0;
        long data;

        // Handle all pairs
        while (length > 1) {
            data = (((buf[i] << 8) & 0xFF00) | ((buf[i + 1]) & 0xFF));
            sum += data;
            // 1's complement carry bit correction in 16-bits (detecting sign extension)
            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0xFFFF;
                sum += 1;
            }

            i += 2;
            length -= 2;
        }

        // Handle remaining byte in odd length buffers
        if (length > 0) {
            sum += (buf[i] << 8 & 0xFF00);
            // 1's complement carry bit correction in 16-bits (detecting sign extension)
            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0xFFFF;
                sum += 1;
            }
        }

        // Final 1's complement value correction to 16-bits
        sum = ~sum;
        sum = sum & 0xFFFF;
        return sum;
    }

    //Generates the pseudo header, used for TCP checksum
    public static byte[] generatePseudoHeader(TcpFlow data, byte[] b){
        ByteBuffer bb = ByteBuffer.allocate(12+b.length);
        bb.put(data.getDstAdd());
        bb.put(data.getSrcAdd());
        bb.put((byte)0x00);
        bb.put((byte) 0x06);
        bb.put(intToTwoBytes(b.length));
        bb.put(b);
        return bb.array();
    }

    public static byte[] longToFourBytes(long l){
        ByteBuffer bb = ByteBuffer.allocate(8);
        byte[] b = new byte[4];
        bb.putLong(l);
        bb.position(4);
        bb.get(b);
        return b;

    }
    public static byte[] intToTwoBytes(int i){
        ByteBuffer bb = ByteBuffer.allocate(4);
        byte[] b = new byte[2];
        bb.putInt(i);
        bb.position(2);
        bb.get(b);
        return b;
    }

    public static long fourBytesToLong(byte[] b){
        ByteBuffer bb = ByteBuffer.allocate(8);
        bb.position(4);
        bb.put(b);
        bb.position(0);
        return bb.getLong();

    }

}


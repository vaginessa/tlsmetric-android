package de.felixschiller.tlsmetric.modules;

import android.util.Log;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import de.felixschiller.tlsmetric.helper.Const;

/**
 * Parses the IP packets to a forged dump stream for saving to file or to dump.
 *
 */
public class IpPacketParse {
    private ToolBox mTool;
    /*
    * Generate IPv4/IPv6 TestBytes
    * ipv4 max package size = 65535 Byte (2^16-1 Byte)
    * ipv6 max package size = 65575 Byte (2^16-1 Byte + 20 Byte Header)
    */
    // hex 45 = dec 69
    // hex 60 = dec 96
    private byte[] sV4TestByte = new byte[]{(byte) 69};
    private byte[] sV6TestByte = new byte[]{(byte) 96};
    private String mCheckV4;
    private String mCheckV6;

    public IpPacketParse(ToolBox tool) {
        mTool = tool;
        //init tmp string to avoid null arrays.
        String tmp = printHexBinary(sV4TestByte);
        mCheckV4 = tmp.substring(0, 2);
        tmp = printHexBinary(sV6TestByte);
        mCheckV6 = tmp.substring(0, 2);
    }

//
//    public L4Payload processPacket(ByteBuffer buffer) {
//        //Get IF Version
//        buffer.position(0);
//        byte[] testbyte = new byte[1];
//        buffer.get(testbyte);
//        int version = getIpVersion(testbyte);
//        // if ipv4 packet
//        if (version == 4) {
//            //Get ipv4 src and dst addresses
//            byte[] srcAdd = new byte[4];
//            byte[] dstAdd = new byte[4];
//            buffer.position(12);
//            buffer.get(srcAdd);
//            buffer.position(16);
//            buffer.get(dstAdd);
//            int ihl = getIHL(testbyte);
//            buffer.position(ihl + 20);
//            byte[] l4Payload = new byte[buffer.capacity() - ihl - 20];
//            buffer.get(l4Payload);
//
//            //process L4 Packet - soruce and destination ports.
//            byte[] srcPort = new byte[2];
//            byte[] dstPort = new byte[2];
//            buffer.position(ihl);
//            buffer.get(srcPort);
//            buffer.get(dstPort);
//            int srcP = srcPort[0] | srcPort[1] << 8;
//            int dstP = dstPort[0] | dstPort[1] << 8;
//            // write socket information to SocketData
//            // Stop here and Log!
//            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Version: ipv" + version
//                    + " srcAdd: " + printHexBinary(srcAdd) + " " + getAddressString(srcAdd)
//                    + " dstAdd: " + printHexBinary(dstAdd) + " " + getAddressString(dstAdd)
//                    + " srcPort " + srcP + " dstPort " + dstPort
//                    + " ihl and testbyte: " + ihl + ", " + printHexBinary(testbyte)
//                    + " L4Payload: " + printHexBinary(l4Payload));
//            Channels.getInstance().add(srcP, new TcpFlow(version, srcAdd, dstAdd, srcP, dstP, new Timestamp(System.currentTimeMillis()), version));
//            return new L4Payload(srcP, l4Payload, false);
//        }
//        else if (version == 6) {
//            //TODO: implement v6 processing
//            return new L4Payload(-6, new byte[1], true);
//        }
//        else {
//            return new L4Payload(-1, new byte[1], true);
//        }
//    }

    /*
    * Gets the first 8 bytes of ip header data and determines the packet length
    */
    public int getPacketLength(ByteBuffer header, int version) {
        /*
        * IPv4 Packet:
        * Header: 0-3 Version, 4-7 IHL (value * 32Bit), 8-15 TOS; 16-31 Total Length
        *
        * IPv6 Packet
        * Header: 0-3 Version, 4-11 Traffic Class, 12-31 Flow Label, 32 - 15 Payload Length,
        * 16-23 Next Header, 24 - 63 Hop Limit
        */

        // Get the IP-Protocol version: 4 == IPv4, 6 == IPv6, Error == -1
        // Ipv4 Packet?
        if (version == 4) {
            //Read total packet length field
            ByteBuffer v4header;
            v4header = header.get(new byte[2], 2, 2);
            int length = v4header.getInt();
            //log that
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG,
                    "IpVersion = v4. \n packetlength = " + length + " Bytes.");
            return length;

            // IPv6 Packet?
        } else if (version == 6) {
            //Read packet payload length field
            ByteBuffer v6header;
            v6header = header.get(new byte[2], 4, 2);
            // IPv6 header is always 40 Bit
            int length = v6header.getInt() + 40;
            //log that
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG,
                    "IpVersion = v6. \n packetlength = " + length + " Bytes.");
            return length;
        } else {
            //log that
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG,
                    "IpVersion = NOT_RECOGNIZED. \n packetlength = " + 0 + " Bytes.");
            return 0;
        }

    }

    /*
    * Get the IP Version by the first 8 Header Bytes
    */
    public int getIpVersion(byte[] testbyte) {
        /*
        * Get First Byte of header, test first 4 Bit if IPv4 or Ipv6
        * Return the IP-Protocol version: 4 == IPv4, 6 == IPv6, Error == -1
        */

        String testVal = printHexBinary(testbyte).substring(0, 2);

        // Ipv4 Packet?
        if (testVal.equals(mCheckV4)) {
            int version = 4;
            //log that
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG,
                    "IpVersion = v4. \n TestByte " + printHexBinary(testbyte) + " ->" + testVal
                            + "\n Ipv4 TestByte: " + printHexBinary(sV4TestByte) + " ->" + mCheckV4);
            return version;

            // IPv6 Packet?
        } else if (testVal.equals(mCheckV6)) {
            int version = 6;
            //log that
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG,
                    "IpVersion = v4. \n TestByte " + printHexBinary(testbyte) + " ->" + testVal
                            + "\n Ipv4 TestByte: " + printHexBinary(sV6TestByte) + " ->" + mCheckV6);
            return version;
        } else {
            //log that
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG,
                    "IpVersion = COULD_NOT_RESOLVE. \n TestByte " + printHexBinary(testbyte)
                            + "\n Ipv4 TestByte: " + printHexBinary(sV4TestByte)
                            + "\n Ipv6 TestByte: " + printHexBinary(sV6TestByte));
            return -1;
        }
    }

    /*
    * read x bytes from stream. This is necessary to read bit-octets instead of the signed integers, provided by FileInputStream class .
    */
    public ByteBuffer readBytes(FileInputStream in, int length) {
        ByteBuffer buff = ByteBuffer.allocate(length);
        try {
            for (int i = 0; i < length; i++) {
                buff.put((byte) in.read());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return buff;
    }

    /*
     * Translates the complement integer representation of java  to readable (String) and
     * usable(hex numbers) representations.
     *
     * Reference:
     * java primitive byte to common understood byte:
     * 0 = 0
     * 1 = 1
     * ...
     * 127 = 127
     * -128 = 128
     * -127 = 129
     * ...
     * - 2 = 254
     * -1 = 255
     * 0 = 256
     *
     * The methods are taken from JDK1.7.x javax.xml.bind.DatatypeConverter.
     * The bind lib is not available on Android.
     */
    public byte[] parseHexBinary(String s) {
        final int len = s.length();

        // "111" is not a valid hex encoding.
        if (len % 2 != 0)
            throw new IllegalArgumentException("hexBinary needs to be even-length: " + s);

        byte[] out = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            int h = hexToBin(s.charAt(i));
            int l = hexToBin(s.charAt(i + 1));
            if (h == -1 || l == -1)
                throw new IllegalArgumentException("contains illegal character for hexBinary: " + s);

            out[i / 2] = (byte) (h * 16 + l);
        }

        return out;
    }

    private int hexToBin(char ch) {
        if ('0' <= ch && ch <= '9') return ch - '0';
        if ('A' <= ch && ch <= 'F') return ch - 'A' + 10;
        if ('a' <= ch && ch <= 'f') return ch - 'a' + 10;
        return -1;
    }

    private final char[] hexCode = "0123456789ABCDEF".toCharArray();

    public String printHexBinary(byte[] data) {
        StringBuilder r = new StringBuilder(data.length * 2);
        for (byte b : data) {
            r.append(hexCode[(b >> 4) & 0xF]);
            r.append(hexCode[(b & 0xF)]);
        }
        return r.toString();
    }

    // get the ipv4 header length
    public int getIHL(byte[] testbyte) {
        String test = printHexBinary(testbyte).substring(1, 2);
        switch (test) {
            case "5":
                return 20;
            case "6":
                return 24;
            case "7":
                return 28;
            case "8":
                return 32;
            case "9":
                return 36;
            case "A":
                return 40;
            case "B":
                return 44;
            case "C":
                return 48;
            case "D":
                return 52;
            case "E":
                return 56;
            case "F":
                return 60;
            default:
                return 20;
        }
    }
    // get the address as string
    public String getAddressString(byte[] hexAddr) {
        if (hexAddr.length == 4){
            String stringAddr = (int)hexAddr[0] + "." + (int)hexAddr[1] + "." + (int)hexAddr[2] + "." + (int)hexAddr[3];
            return stringAddr;
        }
        if (hexAddr.length == 16){
            // TODO with tests!
            return "0000:0000:0000:0000:0000:0000:0000:6666";
        }
        else return "255.255.255.666";

    }
}


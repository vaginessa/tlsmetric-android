import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

public class TestIpPacketParse {
    //use the tools
    /*
    * Generate IPv4/IPv6 TestBytes
    * ipv4 max package size = 65535 Byte (2^16-1 Byte)
    * ipv6 max package size = 65575 Byte (2^16-1 Byte + 20 Byte Header)
    */
    private Byte mV4TestByte = (byte)96;
    private Byte mV6TestByte = (byte)106;
    /*
    * Parses the bytes from the ip Packet to forged ethernet packet dump
    */
    public ByteBuffer parsePackets(ByteBuffer buffer){
        //TODO: build method
        return buffer;
    }
    public Boolean appendToFile(ByteBuffer buffer){
        try {
            FileOutputStream dump = new FileOutputStream("testout.pcap");
        }catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
    /*
    * Gets the first 8 bytes of ip header data and determines the packet length
    */
    public int getPacketLength(ByteBuffer header){
        /*
        * IPv4 Packet:
        * Header: 0-3 Version, 4-7 IHL (value * 32Bit), 8-15 TOS; 16-31 Total Length
        *
        * IPv6 Packet
        * Header: 0-3 Version, 4-11 Traffic Class, 12-31 Flow Label, 32 - 15 Payload Length,
        * 16-23 Next Header, 24 - 63 Hop Limit
        */

        // Get the IP-Protocol version: 4 == IPv4, 6 == IPv6, Error == -1
        int testInt = getIpVersion(header);
        // Ipv4 Packet?
        if (testInt == 4){
            //Read total packet length field
            ByteBuffer v4header;
            v4header = header.get(new byte[2], 2, 2);
            int length = v4header.getInt();
            //log that
            System.out.println("IpVersion = v4. \n packetlength = " + length + " Bytes.");
            return length;

            // IPv6 Packet?
        } else if (testInt == 6){
            //Read packet payload length field
            ByteBuffer v6header;
            v6header = header.get(new byte[2], 4, 2);
            // IPv6 header is always 40 Bit
            int length = v6header.getInt() + 40;
            //log that
            System.out.println(
                    "IpVersion = v6. \n packetlength = " + length + " Bytes.");
            return length;
        } else {
            //log that
            System.out.println(
                    "IpVersion = NOT_RECOGNIZED. \n packetlength = " + 0 + " Bytes.");
            return 0;
        }

    }
    /*
    * Get the IP Version by the first 8 Header Bytes
    */
    public int getIpVersion(ByteBuffer header ){
        /*
        * Get First Byte of header, test first 4 Bit if IPv4 or Ipv6
        * Return the IP-Protocol version: 4 == IPv4, 6 == IPv6, Error == -1
        */
        Byte testByte = header.get();

        // Ipv4 Packet?
        System.out.println("m4Testbyte" + mV4TestByte.toString());
        System.out.println("m6Testbyte" + mV6TestByte.toString());
        if (testByte.toString().substring(0, 3).equals(mV4TestByte.toString().substring(0, 3))){
            int version = 4;
            //log that
            System.out.println(
                    "IpVersion = v4. \n TestByte " + testByte.toString()
                            + "\n Ipv4 TestByte: " + mV4TestByte.toString());
            return version;

            // IPv6 Packet?
        } else if (testByte.toString().substring(0,3).equals(mV6TestByte.toString().substring(0,3))){
            int version = 6;
            //log that
            System.out.println(
                    "IpVersion = v4. \n TestByte " + testByte.toString()
                            + "\n Ipv6 TestByte: " + mV6TestByte.toString());
            return version;
        } else {
            //log that
            System.out.println(
                    "IpVersion = COULD_NOT_RESOLVE. \n TestByte " + testByte.toString()
                            + "\n Ipv4 TestByte: " + mV4TestByte.toString()
                            + "\n Ipv6 TestByte: " + mV6TestByte.toString());
            return -1;
        }
    }
    /*
    * read x bytes from stream. This is necessary to read bit-octets instead of the signed integers, provided by FileInputStream class .
    */
    public ByteBuffer readBytes(FileInputStream in, int length){
        ByteBuffer buff = ByteBuffer.allocate(length);
        try {
            for (int i = 0; i < length; i++) {
                buff.put((byte)in.read());
            }
        } catch (IOException e){
            e.printStackTrace();
        }
        return buff;
    }

}
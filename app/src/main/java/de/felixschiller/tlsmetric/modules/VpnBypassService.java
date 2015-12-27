package de.felixschiller.tlsmetric.modules;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.text.Selection;
import android.util.Log;


import com.voytechs.jnetstream.codec.Decoder;
import com.voytechs.jnetstream.codec.Packet;
import com.voytechs.jnetstream.io.EOPacketStream;
import com.voytechs.jnetstream.io.QueuePacketInputStream;
import com.voytechs.jnetstream.io.StreamFormatException;
import com.voytechs.jnetstream.npl.SyntaxError;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;


import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.sql.Timestamp;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;

import de.felixschiller.tlsmetric.R;
import de.felixschiller.tlsmetric.helper.Const;
import de.felixschiller.tlsmetric.helper.PacketGenerator;
import de.felixschiller.tlsmetric.helper.QueuePacket;
import de.felixschiller.tlsmetric.helper.SocketData;
import de.felixschiller.tlsmetric.helper.TcpFlow;
import de.felixschiller.tlsmetric.helper.UdpFlow;

/**
 * A VPN bypass service to route the network packages to the device itself
 * VPN service has been taken and modified for own purpose from:
 *  - http://www.thegeekstuff.com/2014/06/android-vpn-service/
*/
public class VpnBypassService  extends VpnService {

    //Thread
    private Thread mThread;
    private ParcelFileDescriptor mInterface;

    // Keys for all channels are the source ports (client ports) of the outgoing connection.
    public static Selector mSelector;
    public static Queue<QueuePacket> mSendQueue = new LinkedList<>();

    //a. Configure a builder for the interface.
    Builder builder = new Builder();

    // Packet stream decoder JnetStream:
    private QueuePacketInputStream mPin;
    public static QueuePacketInputStream mClone;
    private Decoder mDecoder;
    private FileInputStream mIn;
    private FileOutputStream mOut;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Stop the previous session by interrupting the thread.
        if (mThread != null) {
            mThread.interrupt();
        }


        //Init selector and jnet package streams
        try {
            mSelector = Selector.open();

            mPin = new QueuePacketInputStream();
            mClone = new QueuePacketInputStream();
            mDecoder = new Decoder(mPin);
        } catch (IOException | SyntaxError | StreamFormatException | EOPacketStream e) {
            e.printStackTrace();
        }

        // Start a new session by creating a new thread.
        mThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    //Configure the TUN interface.
                    mInterface = builder.setSession("VPNBypassService")
                            .addAddress("10.0.2.1", 32)
                            .addRoute("0.0.0.0", 1)
                            .addRoute("128.0.0.0", 1)
                            .establish();
                    //Get FileStream
                    mIn = new FileInputStream(mInterface.getFileDescriptor());
                    mOut = new FileOutputStream(mInterface.getFileDescriptor());

                    /*
                     * This is the main method for the VPN Bypass service. It is split in two parts.
                      *
                     * 1. Read incoming packages from TUN, extracts the layer 4 payload data, opens
                     * channels to the designated hosts and sends the data when the channels are connected.
                     *
                     * 2. Read from the connected channels if data is available and forges the
                     * Layer 3 associate layer 3 (network) and layer 4 (transport) headers and writes
                     * them back to the TUN interface.
                     */
                    while (true) {
                        try {
                            // Initialize byte array with 65535 bytes = maxsize of an IP Packet
                            byte[] b = new byte[65535];

                            // If data is available, read it and process it for the designated channel
                            int available = mIn.read(b);
                            if (available > 0) {
                                sendPacket(b, available);
                                if (Const.IS_DEBUG)Log.d(Const.LOG_TAG, available + " available at TUN interface.");
                            } else {
                                    if (Const.IS_DEBUG)Log.d(Const.LOG_TAG, "no data available at TUN interface.");
                            }

                            //read from sockets where data is available and process it for writeback to TUN
                                readConnections();

                        } catch (IOException e) {
                            e.printStackTrace();
                        }

                        //TODO adjust Value, 1000 is for debuging purpose
                        Thread.sleep(1000);
                    }

                } catch (Exception e) {
                    // Catch any exception
                    e.printStackTrace();
                } finally {
                    try {
                        if (mInterface != null) {
                            mInterface.close();
                            mInterface = null;
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }

        }, "VpnBypassRunnable");

        //start the service
        mThread.start();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (Const.IS_DEBUG) Log.d(getString(R.string.app_name), "Destroy VpnBypassService.");
        if (mThread != null) {
            mThread.interrupt();
        }
        super.onDestroy();
    }

    /*
     * Recieves a packet from internal TUN interface. Strips the packet of the payload and sends
     * it to the designated server. For UDP payload a DatagramChannel, for tcp a SocketChannel is
     * opened and addressed by the source port of the original connection (TUN interface side).
     * Closing of channels is handles by the packet recieving method.
     *
     */
    private void sendPacket(byte[] b, int available) throws IOException, StreamFormatException, SyntaxError {


        //Allocate buffer and read from TUN interface and dump it
        ByteBuffer bb = ByteBuffer.allocate(available);
        bb.put(b, 0, available);
        b = bb.array();
        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Packet from TUN: " + ToolBox.printExportHexString(b));

        //Dump the packet and process it, if ip header is identified.
        Packet pkt = dumpPacket(b);
        if(pkt != null) {

            //Extract connection information
            SocketData data = ConnectionHandler.extractFlowData(pkt);

            if(data.getTransport() == SocketData.Transport.TCP){
                PacketGenerator.handleFlow((TcpFlow)data, pkt.getHeader("TCP"), b.length - data.offset);
                byte[] controlPacket = PacketGenerator.handleFlags((TcpFlow)data);
                if(controlPacket != null){
                    dumpPacket(b);
                    mOut.write(controlPacket);

                }
            }
            //Process outgoing send
            ManageSending(data, pkt, b);
        }
    }

    /*
     * Read from active sockets and channels and generate the feedback ip-packet
     */
    private void readConnections() throws IOException, StreamFormatException, SyntaxError {

        byte[] b = ManageReceiving();

        //If there is any usable data, write it back to TUN interface
        if (b != null) {
            Packet pkt = dumpPacket(b);
            mOut.write(b);
            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, pkt.getSummary());
        }

    }

    /*
     * Creates a IP packet dump of the given byte array and adds it to a separated clone buffer for
     * later processing.
     */
    private Packet dumpPacket(byte[] b) throws IOException, StreamFormatException, SyntaxError {

        Timestamp timestamp = new Timestamp(System.currentTimeMillis());

        //Add b to input buffer and try to determine decode the ip packet
        mPin.addBuffer(b, "IPv4", timestamp);
        Packet pkt = mDecoder.nextPacket();
        if (pkt.hasHeader("IPv4")) {
            mClone.addBuffer(b, "IPv4", timestamp);
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, pkt.getSummary());
            return pkt;
        } else {
            mPin.addBuffer(b, "IPv6", timestamp);
            pkt = mDecoder.nextPacket();
            if (pkt.hasHeader("IPv6")) {
                mClone.addBuffer(b, "IPv6", timestamp);
                if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, pkt.getSummary());
                return pkt;
            } else {
                Log.e(Const.LOG_TAG, "Could not determine IP-Header version");
                return null;
            }
        }
    }


    /*
     * Sends the packet over an existing connection or registers a new channel to the selector.
     */
    public void ManageSending(SocketData data, Packet pkt, byte[] b) throws IOException {

        mSelector.selectNow();
        Set allKey = VpnBypassService.mSelector.selectedKeys();
        Iterator<SelectionKey> keyIterator = allKey.iterator();
        boolean newChannel = true;
        SelectionKey key;

        //When channel is existent, send the packet
        while (keyIterator.hasNext()) {
            key = keyIterator.next();
            SocketData attachedFlow = (SocketData) key.attachment();
            if (attachedFlow.getSrcPort() == data.getSrcPort()) {
                //If it is a tcp packet, handle the flow information
                if (attachedFlow.getTransport() == SocketData.Transport.TCP) {
                    PacketGenerator.handleFlow((TcpFlow) attachedFlow, pkt.getHeader("TCP"), b.length - attachedFlow.offset);
                    key.attach(attachedFlow);
                }
                //send when channel is ready to write, else add to queue
                if (key.isWritable()) {
                    sendPacket(b, key);
                } else {
                    VpnBypassService.mSendQueue.add(new QueuePacket(key, b));
                    if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Could not write to channel ID: " + data.getSrcPort() + ", adding packet to queue");
                }
                newChannel = false;
            }
        }

        // If channel not existent, open it:
        if (newChannel) {
            key = registerChannel(data);
            if (key == null) {
                Log.e(Const.LOG_TAG, "Could not register Channel. ID: " + data.getSrcPort());
            } else if (data.getTransport() == SocketData.Transport.TCP) {
                if (key.isWritable()) {
                    sendPacket(b, key);
                } else {
                    VpnBypassService.mSendQueue.add(new QueuePacket(key, b));
                    Log.d(Const.LOG_TAG, "Could not write to channel ID: " + data.getSrcPort() + ", adding packet to queue");
                }

            } else if(data.getTransport() == SocketData.Transport.UDP) {
                sendPacket(b, key);
            }
        }


        //If send queue is not empty, send it.
        if(!VpnBypassService.mSendQueue.isEmpty()) {
            QueuePacket qPkt = VpnBypassService.mSendQueue.peek();
            if(qPkt.key.isWritable()) {
                sendPacket(qPkt.b, qPkt.key);
                VpnBypassService.mSendQueue.remove();
            }
        }
    }

    /*
     * Sends the packet out, if there's paylaod
     */
    public static void sendPacket(byte[] b, SelectionKey key) throws IOException {
        SocketData data = (SocketData)key.attachment();
        int payload = b.length - data.offset ;
        if(payload > 0) {
            ByteBuffer bb = ByteBuffer.allocate(payload);
            bb.put(b, data.offset, b.length - data.offset);
            bb.position(0);
            if(data.getTransport() == SocketData.Transport.TCP) {
                SocketChannel sChan = (SocketChannel)key.channel();
                int sent = sChan.write(bb);
                Log.d(Const.LOG_TAG, "Sent " + sent + " of "+ payload + " bytes to "
                        + data.getDstAdd() + ":" + data.getDstPort() + "\n" + ToolBox.printExportHexString(b));
            }
            else if(data.getTransport() == SocketData.Transport.UDP) {
                DatagramChannel dChan = (DatagramChannel)key.channel();
                int sent = dChan.write(bb);
                Log.d(Const.LOG_TAG, "Sent " + sent + " of "+ payload + " bytes to "
                        + data.getDstAdd() + ":" + data.getDstPort() + "\n" + ToolBox.printExportHexString(b));
            } else {
                Log.d(Const.LOG_TAG, "Packet not sent. Payload: " + payload);
            }
        } else {
            Log.d(Const.LOG_TAG, "Packet not sent. No Payload.");
        }
    }



    /*
    * Register, connect and protect the Channel by flow-data
    */
    public SelectionKey registerChannel(SocketData data) throws IOException {

        SelectionKey key = null;
        if(data.getTransport() == SocketData.Transport.TCP) {
            TcpFlow flow = (TcpFlow) data;
            SocketChannel socketChannel = SocketChannel.open();
            socketChannel.configureBlocking(false);
            int interestSet = SelectionKey.OP_READ | SelectionKey.OP_WRITE | SelectionKey.OP_CONNECT;
            key = socketChannel.register(mSelector, interestSet, data);
            if (!protect(socketChannel.socket())) {
                Log.e(Const.LOG_TAG, "Could not protect socket");
            } else {
                InetSocketAddress socksAdd = new InetSocketAddress(InetAddress.getByAddress(flow.getDstAdd()), flow.getDstPort());
                socketChannel.connect(socksAdd);
                if (Const.IS_DEBUG) {
                    Log.d(Const.LOG_TAG, "Connecting SocketChannel to: " + socksAdd.getAddress() + ":" + socksAdd.getPort());
                }
            }
        }
        else if(data.getTransport() == SocketData.Transport.UDP) {
            UdpFlow flow = (UdpFlow) data;
            DatagramChannel datagramChannel = DatagramChannel.open();
            datagramChannel.configureBlocking(false);
            key = datagramChannel.register(VpnBypassService.mSelector, SelectionKey.OP_READ, data);
            if (!protect(datagramChannel.socket())) {
                Log.e(Const.LOG_TAG, "Could not protect socket");
            } else {

                datagramChannel.connect(new InetSocketAddress(InetAddress.getByAddress(flow.getDstAdd()), flow.getDstPort()));
                if (Const.IS_DEBUG) {
                    InetSocketAddress socksAdd = (InetSocketAddress) datagramChannel.socket().getRemoteSocketAddress();
                    Log.d(Const.LOG_TAG, "Connecting DatagramChannel to: " + socksAdd.getAddress().toString() + ":" + socksAdd.getPort());
                }
            }
        }
        return key;
    }
    /*
    * If there is readable data at the channels, a forged packet based on the flow data will be returned.
    */
    public static byte[] ManageReceiving() throws IOException {

        //TODO: TCP Flow control!

        Set<SelectionKey> keySet = VpnBypassService.mSelector.selectedKeys();
        Iterator<SelectionKey> keyIterator = keySet.iterator();
        byte[] b = null;
        //Read bytes where channels have data available
        while (keyIterator.hasNext()) {
            SelectionKey key = keyIterator.next();
            if(key.isReadable()) {
                ByteBuffer bb = ByteBuffer.allocate(65535);
                int read = 0;
                SocketData data = (SocketData) key.attachment();
                if (data.getTransport() == SocketData.Transport.TCP) {
                    TcpFlow flow = (TcpFlow) data;
                    SocketChannel sChan = (SocketChannel) key.channel();
                    read = sChan.read(bb);
                }
                if (data.getTransport() == SocketData.Transport.UDP) {
                    UdpFlow flow = (UdpFlow) data;
                    DatagramChannel sChan = (DatagramChannel) key.channel();
                    read = sChan.read(bb);
                }

                //Read the bytes to an array and generate a forged packet based on the flow data
                if (read > 0){
                    b = new byte[read];
                    bb.position(0);
                    bb.get(b);
                    b = PacketGenerator.generatePacket(data, b);
                    //If TCP, write back flow information
                    if(data.getTransport() == SocketData.Transport.TCP){
                        key.attach((TcpFlow)data);
                    }
                    if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, read + "Bytes read from channel ID: "
                            + data.getSrcPort() + "\n" + ToolBox.printExportHexString(b));

                    return b;
                }
                else{
                    if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Could not read from channel ID: " + data.getSrcPort());
                }
            }
            keyIterator.remove();

        }
        return b;
    }

}
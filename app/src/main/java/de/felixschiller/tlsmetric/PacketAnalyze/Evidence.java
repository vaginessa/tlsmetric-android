package de.felixschiller.tlsmetric.PacketAnalyze;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

import com.voytechs.jnetstream.codec.Header;
import com.voytechs.jnetstream.codec.Packet;
import com.voytechs.jnetstream.primitive.address.Address;


import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.Assistant.ContextSingleton;
import de.felixschiller.tlsmetric.Assistant.ExecuteCommand;
import de.felixschiller.tlsmetric.Assistant.ToolBox;
import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Empty;
import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Filter;
import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Identifyer;
import de.felixschiller.tlsmetric.R;

/**
 * Class for generating connection information (Announcements) from packets, which has been
 * detected by the filters.
 */
public class Evidence {

    public static ArrayList<Announcement> mEvidence;
    public static HashMap<Integer, ArrayList<Announcement>> mEvidenceDetail;
    public static boolean newData;
    public static File mResolveFile;
    public static HashMap<Integer, PackageInformation> mPacketInfoMap;
    public static HashMap<Integer, Integer> mPortPidMap = new HashMap<>();
    public static HashMap<Integer, Integer> mUidPidMap = new HashMap<>();

    public Evidence(){
        mEvidence = new ArrayList<>();
        mEvidenceDetail = new HashMap<>();
        newData = false;
        mResolveFile =  new File(ContextSingleton.getContext().getFilesDir() + File.separator + Const.FILE_RESOLVE_PID);
        mPacketInfoMap = new HashMap<>();
        updatePortPidMap();
        updateConnections();

    }

    public void updateConnections(){
        Set<Integer> ports = mPortPidMap.keySet();
            for(int i =0; i< mEvidence.size(); i++){
                int con = mEvidence.get(i).srcPort;
                if (ports.contains(con)){
                    ports.remove(con);
                }
            }
        for (int port: ports) {
            Announcement ann = new Announcement();
            ann.filter = new Empty(Filter.Protocol.UNKNOWN,-1,"No connection data.");
            ann.srcPort = port;
            fillAppData(ann);
            ann.url = "unknown";
            addEvidenceEntry(ann);
        }
   }

    public void processPacket(Packet pkt) {
        Filter filter = scanPacket(pkt);
        if (filter != null) {
            if (Const.IS_DEBUG) Log.d(Const.LOG_TAG, "Filter triggered: " + filter.protocol);
            Announcement ann = generateAnnouncement(pkt, filter);
            addEvidenceEntry(ann);
        }

    }

    private void addEvidenceEntry(Announcement ann){

        boolean updated = false;

        //Check and update existing connections with lesser filter severity or unknown connection (4)
        for(int i =0; i< mEvidence.size(); i++){
            if(mEvidence.get(i).srcPort == ann.srcPort){
                updated = true;
                if(mEvidence.get(i).filter.severity < ann.filter.severity || mEvidence.get(i).filter.severity == 4){
                    mEvidence.set(i, ann);
                }
            }
        }

        //Add found filters if connection not yet exist
        if(!updated){
            if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Adding connection " + ann.url + "to evidence list.");
            mEvidence.add(ann);
        }

        //Add all found filters to the detail list
        if(mEvidenceDetail.containsKey(ann.srcPort)){
            mEvidenceDetail.get(ann.srcPort).add(ann);
        } else {
            ArrayList<Announcement> newList = new ArrayList<>();
            newList.add(ann);
            mEvidenceDetail.put(ann.srcPort, newList);
        }
    }

    private Filter scanPacket(Packet pkt) {

        if (pkt.hasHeader("TCP") && pkt.hasDataHeader()) {
            byte[] b = pkt.getDataValue();
            //if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, b.length + " Bytes data found");
            if (b.length > 0){
                ByteBuffer bb = ByteBuffer.allocate(b.length);
                bb.put(b);

                byte[] identChunk;
                if (b.length >= 12){
                    identChunk = new byte[20];
                } else {
                    identChunk = new byte[b.length];
                }

                bb.position(0);
                try {
                    bb.get(identChunk);
                }catch (BufferOverflowException |BufferUnderflowException e) {
                    Log.e(Const.LOG_TAG, "Could not read identChunk from TCP packet.");
                }
                return Identifyer.indent(identChunk);
            } else return null;
        } else {
            return null;
        }
    }

    public static Announcement generateAnnouncement(Packet pkt, Filter filter) {
        Announcement ann = new Announcement();
        ann.filter = filter;
        fillConnectionData(ann, pkt);
        fillAppData(ann);
        return ann;
    }

    private static void fillConnectionData(Announcement ann, Packet pkt) {
        Header ipHeader;
        Header transportHeader;
        ann.timestamp = new Timestamp(System.currentTimeMillis());
        //Read ip and transport Header
        if (pkt.hasHeader("IPv4")) {
            ipHeader = pkt.getHeader("IPv4");
        } else if (pkt.hasHeader("IPv6")){
            ipHeader = pkt.getHeader("IPv6");
        } else {
            ipHeader = null;
        }

        if (pkt.hasHeader("TCP") && ipHeader != null) {
            transportHeader = pkt.getHeader("TCP");
        }else if (pkt.hasHeader("UDP") && ipHeader != null ) {
            transportHeader = pkt.getHeader("UDP");
        } else {
            transportHeader = null;
        }

        if(ipHeader != null && transportHeader != null) {
            InetAddress localAddress = ToolBox.getLocalAddress();

            try {
            //Get ports and addresses from header
            Address address = (Address)ipHeader.getValue("daddr");
            InetAddress remoteaddress = InetAddress.getByAddress(address.toByteArray());
                if(localAddress != null &&
                        !localAddress.getHostAddress().equals(remoteaddress.getHostAddress())){
                    ann.dstAddr = remoteaddress;
                    ann.dstPort = (int) transportHeader.getValue("dport");
                    ann.srcPort = (int) transportHeader.getValue("sport");
                } else {
                    address = (Address)ipHeader.getValue("saddr");
                    ann.dstAddr = InetAddress.getByAddress(address.toByteArray());
                    ann.srcPort = (int) transportHeader.getValue("dport");
                    ann.dstPort = (int) transportHeader.getValue("sport");
                }
            } catch (UnknownHostException e) {
                e.printStackTrace();
            }
            if(ann.dstAddr != null)ann.url = ann.dstAddr.getHostName();
        }
    }

    private static void fillAppData(Announcement ann) {
        ann.pid = getPidByPort(ann.srcPort);

        if (ann.pid >= 0 && !mPacketInfoMap.containsKey(ann.pid)){
            PackageManager pm = ContextSingleton.getContext().getPackageManager();
            ActivityManager am = (ActivityManager) ContextSingleton.getContext().getSystemService(Context.ACTIVITY_SERVICE);
            PackageInformation pi = new PackageInformation();
            pi.pid = ann.pid;

            List<ActivityManager.RunningAppProcessInfo> pids = am.getRunningAppProcesses();
            for (int i = 0; i < pids.size(); i++) {
                ActivityManager.RunningAppProcessInfo info = pids.get(i);
                if(info.pid == ann.pid){
                    try {
                        String[] list = info.pkgList;
                        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Processing packet information of: " + list[0]);
                        pi.packageName = list[0];
                        pi.icon = pm.getApplicationIcon(pi.packageName);
                        mPacketInfoMap.put(ann.pid, pi);
                    } catch (PackageManager.NameNotFoundException e) {
                        if(Const.IS_DEBUG)Log.e(Const.LOG_TAG, "Icon and/or package name not found. Using TLSMetric icon for unknown app.");
                    }

                }
            }
        }
    }

    private static int getPidByPort(int port) {
        if(!mPortPidMap.containsKey(port)){
            updatePortPidMap();
            if(mPortPidMap.containsKey(port)){
                return mPortPidMap.get(port);
            } else{
                return -1;
            }
        } else {
            return mPortPidMap.get(port);

        }
    }

    private static void updatePortPidMap() {
        updateUidPidMap();
        HashMap<Integer, Integer> portUidMap = getPortMap();
        Set<Integer> ports = portUidMap.keySet();
        for (int port :ports){
            if(!mPortPidMap.containsKey(port) && mUidPidMap.containsKey(portUidMap.get(port))){
                mPortPidMap.put(port, mUidPidMap.get(portUidMap.get(port)));
                if(Const.IS_DEBUG)Log.d(Const.LOG_TAG,"mapping port to pid: " + port + " ->" + mUidPidMap.get(portUidMap.get(port)));
            }
        }
    }




    public static void updateUidPidMap(){
        ActivityManager am = (ActivityManager) ContextSingleton.getContext().getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningAppProcessInfo> infos = am.getRunningAppProcesses();
        for (ActivityManager.RunningAppProcessInfo info : infos) {
            if(!mUidPidMap.containsKey(info.uid)){
                mUidPidMap.put(info.uid, info.pid);
                if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Adding uid/pid: " + info.uid + " -> " + info.pid);
            }
        }
    }


    public static int[] getPids() {
        ActivityManager am = (ActivityManager) ContextSingleton.getContext().getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningAppProcessInfo> pids = am.getRunningAppProcesses();
        int[] pid = new int[pids.size()];
        for (int i = 0; i < pids.size(); i++) {
            ActivityManager.RunningAppProcessInfo info = pids.get(i);
            pid[i] = info.pid;
        }
        return pid;
    }

    public static HashMap<Integer, Integer> getPortMap() {
        HashMap<Integer, Integer> result = new HashMap<>();
        String commandTcp4 = "cat /proc/net/tcp";
        String commandTcp6 = "cat /proc/net/tcp6";

        parseNetOutput(ExecuteCommand.userForResult(commandTcp4), result);
        parseNetOutput(ExecuteCommand.userForResult(commandTcp6), result);

        return result;
    }

    public static void parseNetOutput(String readIn, HashMap<Integer, Integer> hashMap) {
        String[] splitLines;
        String[] splitTabs;

        splitLines = readIn.split("\\n");
        for (int i = 1; i < splitLines.length; i++) {
            splitLines[i] = splitLines[i].trim();
            while (splitLines[i].contains("  ")) {
                splitLines[i] = splitLines[i].replace("  ", " ");
            }
            splitTabs = splitLines[i].split("\\s");
            int pos = splitTabs[1].indexOf(":");
            String port = splitTabs[1].substring(pos + 1, pos + 5);

            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.position(2);
            bb.put(ToolBox.hexStringToByteArray(port));
            bb.position(0);
            int srcPort = bb.getInt();
            int uid = Integer.parseInt(splitTabs[7]);
            hashMap.put(srcPort, uid);
            if (Const.IS_DEBUG)Log.d(Const.LOG_TAG,"port to uid:" + srcPort + " -> " + uid);
        }
    }

    public static PackageInformation getPackageInformation(int pid) {
        if(mPacketInfoMap.containsKey(pid)){
            return mPacketInfoMap.get(pid);
        } else {
            return generateDummy();
        }

    }

    //Just a BubbleSort - order ArrayList<Announcement> in place by by severity, DESC
    private static void sortAnnList(ArrayList<Announcement> annList){
        int range = annList.size() - 1;
        while(range > 1){
            for(int i = 0; i < range; i ++){
                if(annList.get(i).filter.severity < annList.get(i + 1).filter.severity){
                    Announcement tmpAnn = annList.get(i);
                    annList.set(i, annList.get(i + 1));
                    annList.set(i+1 ,tmpAnn);
                }
            }
            range --;
        }
    }

public static ArrayList<Announcement> getSortedEvidence(){
    sortAnnList(mEvidence);
    return mEvidence;
}
    public static ArrayList<Announcement> getSortedEvidenceDetail(int key){
        sortAnnList(mEvidenceDetail.get(key));
        return mEvidenceDetail.get(key);
    }

    private static PackageInformation generateDummy() {
        PackageInformation pi = new PackageInformation();
        pi.icon = ContextSingleton.getContext().getResources().getDrawable(R.mipmap.icon);
        pi.packageName = "Unknown App";
        return pi;
    }

    /*    public static HashMap<Integer, Integer> generatePortPidMap(){
        if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Generating Port-to-Pid Map.");
        HashMap<Integer, Integer> portPidMap = new HashMap<>();
        HashMap<Integer, Integer> portUidMap = getPortMap();

        Set<Integer> set = portUidMap.keySet();
        for (int key : set) {
            int uid = portUidMap.get(key);
            if(mUidPidMap.containsKey(uid)){
                portPidMap.put(key, mUidPidMap.get(uid));
                if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "PortPidMap matched uid " + uid +
                        "->" + key + ", " + mUidPidMap.get(uid) );
            } else if(uid == 0){
                portPidMap.put(key, 0);
                if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Root uid " + uid +
                        ": " + key + ", " + 0 );
            } else {
                portPidMap.put(key, -1);
                if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Could not match by uid " + uid +
                        ": " + key + ", " + -1 );
            }
        }
    return portPidMap;
    }*/

    /*
    public static HashMap<Integer, Integer> getPidMap(){
        HashMap<Integer, Integer> result = new HashMap<>();
        int[] pids = getPids();

        String[] split;
        for (int pid : pids) {
            String command = "cat /proc/" + pid + "/status";
            String readIn = ExecuteCommand.userForResult(command);
            int pos = readIn.indexOf("Uid:");
            try {
                readIn = readIn.substring(pos, pos + 20);
            } catch (StringIndexOutOfBoundsException e){
                Log.e(Const.LOG_TAG, "Readin of uid of process " + pid + " failed, StringIndexOutOfBounds.");
            }

            split = readIn.split("\\t");
            if(split.length > 1) {
                try {
                    int uid = Integer.parseInt(split[1]);
                    Log.d(Const.LOG_TAG, "pid to uid: " + pid + "->" + uid);
                    result.put(uid, pid);
                } catch (NumberFormatException e) {
                    Log.e(Const.LOG_TAG, "Parsing of UID failed! " + split[1] + " Pid: " + pid);
                    result.put(-1, pid);
                }
            }
        }

        return result;
    }*/

}

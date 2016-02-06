package de.felixschiller.tlsmetric.PacketAnalyze;

import android.graphics.drawable.Icon;


import java.net.InetAddress;
import java.sql.Timestamp;

import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Filter;

/**
 * Created by schillef on 22.01.16.
 */
public class Announcement {

    public InetAddress dstAddr;
    public String url;
    public int srcPort;
    public int dstPort;
    public Timestamp timestamp;

    public int pid;
    public int uid;

    public Filter filter;


    public void touch(){
        timestamp = new Timestamp(System.currentTimeMillis());
    }

}

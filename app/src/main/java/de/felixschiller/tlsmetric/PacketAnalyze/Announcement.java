package de.felixschiller.tlsmetric.PacketAnalyze;

import android.graphics.drawable.Icon;

import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Filter;

/**
 * Created by schillef on 22.01.16.
 */
public class Announcement {

    public byte[] dstAddr;
    public String url;
    public int srcPort;
    public int dstPost;

    public Icon icon;
    public String appName;
    public String appVendor;
    public int pid;

    public Filter filter;
}

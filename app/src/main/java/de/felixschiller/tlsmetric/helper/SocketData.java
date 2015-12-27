package de.felixschiller.tlsmetric.helper;

import java.sql.Timestamp;

public abstract class SocketData {

    private int mVersion;
    private byte[] mSrcAdd;
    private byte[] mDstAdd;
    private int mSrcPort;
    private int mDstPort;
    private Timestamp mTime;
    private Transport mTrans;
    public int offset;

    public SocketData(byte[] srcAdd, byte[] dstAdd, int srcPort, int dstPort, Timestamp time, int ipVersion){
        mVersion = ipVersion;
        mSrcAdd = srcAdd;
        mDstAdd = dstAdd;
        mSrcPort = srcPort;
        mDstPort = dstPort;
        mTime = time;}

    //Getter and Setter
    public int getVersion() { return mVersion; }
    public void setVersion(int version) { this.mVersion = version; }

    public byte[] getSrcAdd() {return mSrcAdd;}
    public void setSrcAdd(byte[] srcAdd) {this.mSrcAdd = srcAdd;}

    public byte[] getDstAdd() {
        return mDstAdd;
    }
    public void setDstAdd(byte[] mSstAdd) {
        this.mDstAdd = mSstAdd;
    }

    public int getSrcPort() {
        return mSrcPort;
    }
    public void setSrcPort(int srcPort) {
        this.mSrcPort = srcPort;
    }

    public int getDstPort() {
        return mDstPort;
    }
    public void setDstPort(int dstPort) {
        this.mDstPort = dstPort;
    }

    public Timestamp getTime(){ return mTime;}
    public void setTime(Timestamp time){mTime = time;}

    public int getIpVersion(){ return mVersion;}
    public void setIpVersion(int ipVersion){ mVersion = ipVersion;}

    public Transport getTransport(){return mTrans;}
    public void setTransport(Transport trans){mTrans = trans; }

    /**
     * Data class for socket pair connections
     */
    public enum Transport{
        TCP,
        UDP
    }
}
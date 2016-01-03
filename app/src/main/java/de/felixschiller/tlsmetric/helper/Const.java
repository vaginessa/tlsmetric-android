package de.felixschiller.tlsmetric.helper;

/**
 * Storing constant values for app
 */

public interface Const {

    boolean IS_DEBUG = true;
    int CHANNEL_TIMEOUT_UDP = 10000;
    int CHANNEL_TIMEOUT_TCP = 3800;

    String LOG_TAG = "TLSMetric";
    String FILE_IF_LIST = "iflist";
    String FILE_TCPDUMP = "tcpdump";
    String FILE_PCAP = "dump.pcap";


}

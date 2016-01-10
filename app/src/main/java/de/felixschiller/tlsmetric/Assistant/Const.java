package de.felixschiller.tlsmetric.Assistant;

/**
 * Storing constant values for app
 */

public interface Const {

    boolean IS_DEBUG = true;
    boolean IS_ROOT = true;

    int CHANNEL_TIMEOUT_UDP = 10000;
    int CHANNEL_TIMEOUT_TCP = 3800;

    String LOG_TAG = "TLSMetric";
    String FILE_IF_LIST = "iflist";
    String FILE_TCPDUMP = "tcpdump";
    String FILE_PCAP = "dump.pcap";


}

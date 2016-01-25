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

    //File info for AnalyzerService
    String FILE_TCPDUMP = "tcpdump";
    String FILE_DUMP = "dump.pcap";
    String FILE_FILTER = "filter.ini";
    String PARAMS = "-w";
    Object FILE_RESOLVE_PID = "resolve";
}

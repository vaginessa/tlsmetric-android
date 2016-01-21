package de.felixschiller.tlsmetric.PacketAnalyze.Filter;

/**
 * Class for Filter rules
 */
public abstract class Filter {
    public Protocol protocol;
    public int severity = 3;
    public String description;
    public boolean checkCypher;

    public Filter(Protocol protocol, int severity, String description) {
        this.protocol = protocol;
        this.severity = severity;
        this.description = description;
    }

    public enum Protocol {
        HTTP,
        SSL2,
        SSL3,
        TLS1_0,
        TLS1_1,
        TLS1_2,
    }

}

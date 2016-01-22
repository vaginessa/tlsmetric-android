package de.felixschiller.tlsmetric.PacketAnalyze.Filter;

import de.felixschiller.tlsmetric.Assistant.ContextSingleton;
import de.felixschiller.tlsmetric.R;

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
    }

    public enum Protocol {
        HTTP,
        SSL2,
        SSL3,
        TLS10,
        TLS11,
        TLS12, SSL1,
    }

}

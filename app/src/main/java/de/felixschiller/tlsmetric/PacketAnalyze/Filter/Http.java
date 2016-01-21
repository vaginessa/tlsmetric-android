package de.felixschiller.tlsmetric.PacketAnalyze.Filter;

/**
 * Created by schillef on 21.01.2016.
 */
public class Http extends Filter {

    public Http(Protocol protocol, int severity, String description) {
        super(protocol, severity, description);
        checkCypher = false;
    }
}

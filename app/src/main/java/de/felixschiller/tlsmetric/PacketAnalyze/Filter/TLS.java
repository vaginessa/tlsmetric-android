package de.felixschiller.tlsmetric.PacketAnalyze.Filter;

/**
 * Created by schillef on 21.01.2016.
 */
public class Tls extends Filter {

    public TLSprotocol mSubProtocol;
    public int mVersion;

    public Tls(Protocol protocol, int severity, String description, TLSprotocol subProtocol, int version) {
        super(protocol, severity, description);
        checkCypher = true;
        mSubProtocol = subProtocol;
        mVersion = version;
    }

    public enum TLSprotocol {
        HANDSHAKE,
        CHANGE_CYPHER,
        ALERT,
        APP_DATA
    }
}

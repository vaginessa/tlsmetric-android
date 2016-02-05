package de.felixschiller.tlsmetric.PacketAnalyze;

import android.util.Log;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.Assistant.ContextSingleton;
import de.felixschiller.tlsmetric.Assistant.ToolBox;
import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Filter;
import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Http;
import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Tls;
import de.felixschiller.tlsmetric.R;


/**
 * Created by schillef on 21.01.2016.
 */
public class Identifyer {


    final static byte[] sHTTP = new byte[]{(byte) 0x48, (byte) 0x54, (byte) 0x54, (byte) 0x50};
    final static byte[] sTLS03 = new byte[]{(byte) 0x03, (byte) 0x00};
    final static byte[] sTLS10 = new byte[]{(byte) 0x03, (byte) 0x01};
    final static byte[] sTLS11 = new byte[]{(byte) 0x03, (byte) 0x01};
    final static byte[] sTLS12 = new byte[]{(byte) 0x03, (byte) 0x03};


    public static Filter indent(byte[] ident) {
        Filter filter = null;

        if (searchByteArray(ident, sHTTP) == 0) filter = new Http(Filter.Protocol.HTTP, 3,
                ContextSingleton.getContext().getResources().getString(R.string.ALERT_HTTP));
        else if (searchByteArray(ident, sTLS03) == 1 && fillSubProto(ident) != null)
            filter = new Tls(Filter.Protocol.SSL3, 0,
                    ContextSingleton.getContext().getResources().getString(R.string.ALERT_TLS_03),
                    fillSubProto(ident), 10);
        else if (searchByteArray(ident, sTLS10) == 1 && fillSubProto(ident) != null)
            filter = new Tls(Filter.Protocol.TLS10, 0,
                    ContextSingleton.getContext().getResources().getString(R.string.ALERT_TLS_10),
                    fillSubProto(ident), 10);
        else if (searchByteArray(ident, sTLS11) == 1 && fillSubProto(ident) != null)
            filter = new Tls(Filter.Protocol.TLS11, 0,
                    ContextSingleton.getContext().getResources().getString(R.string.ALERT_TLS_11),
                    fillSubProto(ident), 11);
        else if (searchByteArray(ident, sTLS12) == 1 && fillSubProto(ident) != null)
            filter = new Tls(Filter.Protocol.TLS12, 0,
                    ContextSingleton.getContext().getResources().getString(R.string.ALERT_TLS_12),
                    fillSubProto(ident), 12);
        return filter;
    }

    private static Tls.TlsProtocol fillSubProto(byte[] ident) {

        switch (ident[0]) {
            case (byte) 0x16:
                return Tls.TlsProtocol.HANDSHAKE;
            case (byte) 0x15:
                return Tls.TlsProtocol.ALERT;
            case (byte) 0x17:
                return Tls.TlsProtocol.APP_DATA;
            case (byte) 0x14:
                return Tls.TlsProtocol.CHANGE_CYPHER;
            default:
                return null;
        }

    }

    public static int searchByteArray(byte[] input, byte[] searchedFor) {
        //convert byte[] to Byte[]
        Byte[] searchedForB = new Byte[searchedFor.length];
        for (int x = 0; x < searchedFor.length; x++) {
            searchedForB[x] = searchedFor[x];
        }

        int idx = -1;
        //search:
        Deque<Byte> q = new ArrayDeque<>(input.length);
        for (int i = 0; i < input.length; i++) {
            if (q.size() == searchedForB.length) {
                //here I can check
                Byte[] cur = q.toArray(new Byte[]{});
                if (Arrays.equals(cur, searchedForB)) {
                    //found!
                    idx = i - searchedForB.length;
                    break;
                } else {
                    //not found
                    q.pop();
                    q.addLast(input[i]);
                }
            } else {
                q.addLast(input[i]);
            }
        }
        if (Const.IS_DEBUG && idx != -1)
            Log.d(Const.LOG_TAG, ToolBox.printHexBinary(searchedFor) + " found at position " + idx);
        return idx;
    }
}

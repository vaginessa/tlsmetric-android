package de.felixschiller.tlsmetric.PacketAnalyze;

import java.util.ArrayList;

/**
 * Created by schillef on 22.01.16.
 */
public class Evidence {

    public static ArrayList<Announcement> annouceList;
    public boolean newData;

    public Evidence(){
        annouceList = new ArrayList<>();
        newData = false;
    }


}

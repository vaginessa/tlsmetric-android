package de.felixschiller.tlsmetric.PacketAnalyze;

import android.graphics.drawable.Drawable;
import android.graphics.drawable.Icon;

/**
 * Information class for detected, communicating apps.
 */
public class PackageInformation {
    public int pid;
    public int uid;
    public Drawable icon;
    public String packageName;
}

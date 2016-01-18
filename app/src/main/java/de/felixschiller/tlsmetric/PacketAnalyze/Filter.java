package de.felixschiller.tlsmetric.PacketAnalyze;

import de.felixschiller.tlsmetric.Assistant.ToolBox;

/**
 * Class for Filter rules
 */
public class Filter {
    public FilterType filterType;
    public String protocol;
    public byte[] value;
    public short severity;
    public String description;

    public Filter(FilterType filter, String protocol, short severity, String description){
        this.filterType = filter;
        this.protocol = protocol;
        this.severity = severity;
        this.description = description;
    }
    public Filter(FilterType filter, String protocol, byte[] value, short severity, String description){
        this.filterType = filter;
        this.protocol = protocol;
        this.value = value;
        if (severity > 3){
            this.severity = 3;
        } else if(severity < 0){
            this.severity = 0;
        } else {
            this.severity = severity;
        }
        this.description = description;
    }

    public String getSummary() {
        if (filterType == FilterType.IS_PRESENT) {
            return filterType.toString() + ", " + protocol + ", " + severity + ", " + description;
        } else if (filterType == FilterType.CONTAINS) {
            return filterType.toString() + ", " + protocol + ", " + ToolBox.printHexBinary(value) + ", " + severity + ", " + description;
        } else {
            return "Filter invalid!";
        }
    }

    public enum FilterType{
        IS_PRESENT,
        CONTAINS;
    }

}

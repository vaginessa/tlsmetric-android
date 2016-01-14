package de.felixschiller.tlsmetric.PacketAnalyze;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

import de.felixschiller.tlsmetric.Assistant.ToolBox;

/**
 * Holds filters for accessing from packet analyzer and can parses them from a given file.
 */
public class FilterRules {
    public static ArrayList<Filter> filterList = new ArrayList<>();


    public static void addFilter(Filter filter) {
        filterList.add(filter);
    }

    public static void parseFilterList(File file){
        String statement;

        try{
            FileReader fr = new FileReader(file);
            BufferedReader br = new BufferedReader(fr);

            while((statement = br.readLine()) != null){
                if(!statement.substring(0,1).equals("#")){
                    generateFilter(statement);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private static void generateFilter(String statement) {
        char separator = ",".toCharArray()[0];
        int current = 0;
        int position = 0;

        String protocol = null;
        String severity = null;
        String description = null;
        String value = null;

        if(statement.contains("IS_PRESENT")){
            for(int i = 0; i < statement.length(); i++ ){
                if(statement.charAt(i) == separator){
                    current++;
                    String result = statement.substring(position, i);
                    switch (current)
                    {
                        case 1:
                            break;
                        case 2:
                        protocol = result;
                            break;
                        case 3:
                        severity = result;
                            break;
                        case 4:
                            description = result;
                            break;
                        default:
                            break;
                    }
                }
            }

            addFilter(new Filter(Filter.FilterType.IS_PRESENT, protocol, (short)(severity.charAt(0)), description));
        }
        if(statement.contains("CONTAINS")){
            for(int i = 0; i < statement.length(); i++ ){
                if(statement.charAt(i) == separator){
                    current++;
                    String result = statement.substring(position, i);
                    switch (current)
                    {
                        case 1:
                            break;
                        case 2:
                            protocol = result;
                            break;
                        case 3:
                            severity = result;
                            break;
                        case 4:
                            description = result;
                            break;
                        case 5:
                            value = result;
                            break;
                        default:
                            break;
                    }
                }
            }
            addFilter(new Filter(Filter.FilterType.CONTAINS, protocol, ToolBox.hexStringToByteArray(value), (short)(severity.charAt(0)), description));
        }
    }


}

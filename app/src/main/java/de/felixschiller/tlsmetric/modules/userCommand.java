package de.felixschiller.tlsmetric.modules;

import com.stericson.RootShell.exceptions.RootDeniedException;
import com.stericson.RootShell.execution.Command;
import com.stericson.RootTools.RootTools;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

/**
 * Helper class for running su commands on the device.
 */
public class userCommand {

    // sets up an command with su rights on the console and logs the output
    public static void doCommand(int id, String com){
        Command command = new Command(id, com)
        {
            @Override
            public void commandOutput(int id, String line) {
                super.commandOutput(id, line);
            }

            @Override
            public void commandTerminated(int id, String reason) {
                super.commandTerminated(id, reason);
            }

            @Override
            public void commandCompleted(int id, int exitcode) {
                super.commandCompleted(id, exitcode);
            }
        };
        try {
            RootTools.getShell(true).add(command);
        }catch (IOException | RootDeniedException | TimeoutException ex) {
            ex.printStackTrace();
        }
    }

}

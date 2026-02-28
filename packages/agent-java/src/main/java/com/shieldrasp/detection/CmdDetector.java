package com.shieldrasp.detection;

import java.util.List;
import com.shieldrasp.RASPBlockException;

public class CmdDetector {
    public static void detect(List<String> command) {
        try {
            for (String arg : command) {
                if (arg.matches(".*[;|&`$><\\n\\\\\\\\].*")) {
                    // Check taint here
                    // if (TaintEngine.isTainted(arg))
                    //     sendTelemetry
                    //     throw new RASPBlockException("[ShieldRASP] Command Injection Blocked");
                }
            }
        } catch (RASPBlockException e) {
            throw e;
        } catch (Throwable t) {
            // Fail open
        }
    }
}

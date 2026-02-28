package com.shieldrasp;

import java.lang.instrument.Instrumentation;
import com.shieldrasp.config.AgentConfig;

public class Agent {
    public static void premain(String agentArgs, Instrumentation inst) {
        AgentConfig config = new AgentConfig();
        if (config.getApiKey() == null || config.getApiKey().isEmpty()) {
            System.err.println("[ShieldRASP] Agent API Key missing, disabling agent.");
            return;
        }
        
        System.out.println("[ShieldRASP] Initializing in " + config.getMode() + " mode");
        inst.addTransformer(new ShieldRaspTransformer());
    }
}

package net.sourceforge.prograde.sm;

import java.security.AccessController;
import java.security.Policy;
import java.security.PrivilegedAction;

import net.sourceforge.prograde.policy.ProgradePolicyFile;

/**
 * Class extending SecurityManager and using ProgradePolicyFile for access controlling.
 * 
 * @author Ondrej Lukas
 */
public class ProgradeSecurityManager extends SecurityManager {

    /**
     * Constructor which also set ProgradePolicyFile as Policy.
     */
    public ProgradeSecurityManager() {
        super();
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                Policy.setPolicy(new ProgradePolicyFile());
                return null;
            }
        });
    }
}

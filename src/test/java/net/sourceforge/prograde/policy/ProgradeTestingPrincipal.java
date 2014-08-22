package net.sourceforge.prograde.policy;

import java.security.Principal;

/**
 * 
 * @author Ondrej Lukas
 */
public class ProgradeTestingPrincipal implements Principal {

    private String name;

    public ProgradeTestingPrincipal(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }
}

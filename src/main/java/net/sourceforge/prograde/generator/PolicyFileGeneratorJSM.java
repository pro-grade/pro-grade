package net.sourceforge.prograde.generator;

/**
 * Class extending SecurityManager and using {@link NotifyAndAllowPolicy} policy with
 * {@link GeneratePolicyFromDeniedPermissions} listener for generating policy file from denied permissions.
 * 
 * @author Josef Cacek
 */
public class PolicyFileGeneratorJSM extends SecurityManager {

    /**
     * JSM Constructor.
     */
    public PolicyFileGeneratorJSM() {
        SecurityActions.setPolicy(new NotifyAndAllowPolicy(null, new GeneratePolicyFromDeniedPermissions()));
    }
}

package net.sourceforge.prograde.generator;

/**
 * Class extending SecurityManager and using {@link NotifyAndAllowPolicy} policy with {@link PrintDeniedPermissions} listener
 * for writing missing permissions to error stream.
 * 
 * @author Josef Cacek
 */
public class DumpMissingPermissionsJSM extends SecurityManager {

    /**
     * JSM Constructor.
     */
    public DumpMissingPermissionsJSM() {
        SecurityActions.setPolicy(new NotifyAndAllowPolicy(null, new PrintDeniedPermissions()));
    }
}

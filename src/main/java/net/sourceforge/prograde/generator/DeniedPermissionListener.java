package net.sourceforge.prograde.generator;

import java.security.Permission;
import java.security.ProtectionDomain;

/**
 * Interface which is used by {@link NotifyAndAllowPolicy} to send information about denied permission and policy refresh event.
 * 
 * @author Josef Cacek
 */
public interface DeniedPermissionListener {

    /**
     * Called when policy doesn't imply permission.
     * 
     * @param pd
     * @param perm
     */
    void permissionDenied(ProtectionDomain pd, Permission perm);

    /**
     * Called after the policy was refreshed.
     */
    void policyRefreshed();

}

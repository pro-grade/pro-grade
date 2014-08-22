package net.sourceforge.prograde.generator;

import java.security.AccessController;
import java.security.Policy;
import java.security.PrivilegedAction;

/**
 * Helper class to keep privileged actions on a single place.
 * 
 * @author Josef Cacek
 */
public class SecurityActions {

    /**
     * Returns a system property value using the specified <code>key</code>.
     * 
     * @param key
     * @return
     */
    static String getSystemProperty(final String key) {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<String>() {
                public String run() {
                    return System.getProperty(key);
                }
            });
        } else {
            return System.getProperty(key);
        }
    }

    /**
     * Returns the installed policy object.
     * 
     * @return
     */
    static Policy getPolicy() {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<Policy>() {
                public Policy run() {
                    return Policy.getPolicy();
                }
            });
        } else {
            return Policy.getPolicy();
        }
    }

    /**
     * Installs given policy object.
     */
    static void setPolicy(final Policy policy) {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            AccessController.doPrivileged(new PrivilegedAction<Void>() {
                public Void run() {
                    Policy.setPolicy(policy);
                    return null;
                }
            });
        } else {
            Policy.setPolicy(policy);
        }
    }
}

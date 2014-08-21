/* Copyright 2014 Josef Cacek
 *
 * This file is part of pro-grade.
 *
 * Pro-grade is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pro-grade is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with pro-grade.  If not, see <http://www.gnu.org/licenses/>.
 */
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

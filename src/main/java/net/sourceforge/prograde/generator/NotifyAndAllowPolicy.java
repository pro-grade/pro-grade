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

import java.security.AllPermission;
import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;

/**
 * Policy wrapper for debug purposes. It's main goal is to report denied permissions to a {@link DeniedPermissionListener}
 * instance. If a checked permission is not an {@link AllPermission} instance, then implementation of the
 * {@link #implies(ProtectionDomain, Permission)} method returns true. If the checked permission is an instance of
 * {@link AllPermission}, then the result of {@link Policy#implies(ProtectionDomain, Permission)} called on wrapped policy is
 * returned.
 * 
 * @author Josef Cacek
 */
public final class NotifyAndAllowPolicy extends Policy {

    private final Policy wrappedPolicy;
    private final DeniedPermissionListener listener;

    /**
     * Default constructor.
     */
    public NotifyAndAllowPolicy() {
        this(null, null);
    }

    /**
     * Constructor.
     * 
     * @param policy policy to be wrapped; if <code>null</code> is given {@link Policy#getPolicy()} is used
     * @param dpListener listener instance to which is reported denied {@link Permission}; if <code>null</code> is given
     *        {@link PrintDeniedPermissions} instance is used
     */
    public NotifyAndAllowPolicy(Policy policy, DeniedPermissionListener dpListener) {
        wrappedPolicy = policy != null ? policy : SecurityActions.getPolicy();
        listener = dpListener != null ? dpListener : new PrintDeniedPermissions();
    }

    /**
     * If a checked permission is not an {@link AllPermission} instance, then returns true. If the checked permission is an
     * instance of {@link AllPermission}, then the result of {@link Policy#implies(ProtectionDomain, Permission)} called on
     * wrapped policy is returned (or false when the wrapped policy is <code>null</code>).
     * <p>
     * When the wrapped policy is null or it doesn't imply checked permission (!=AllPermission), then
     * {@link DeniedPermissionListener#permissionDenied(ProtectionDomain, Permission)} is called.
     * </p>
     * 
     * @param protectionDomain
     * @param permission
     * @return mostly true, but read the JavaDoc :)
     */
    @Override
    public final boolean implies(ProtectionDomain protectionDomain, Permission permission) {
        if (permission instanceof AllPermission) {
            return wrappedPolicy != null ? wrappedPolicy.implies(protectionDomain, permission) : false;
        }
        if (wrappedPolicy == null || !wrappedPolicy.implies(protectionDomain, permission)) {
            try {
                listener.permissionDenied(protectionDomain, permission);
            } catch (Throwable t) {
                t.printStackTrace();
            }
        }
        return true;
    }

    /**
     * Refreshes the wrapped policy and calls {@link DeniedPermissionListener#policyRefreshed()} on the listener used by this
     * policy.
     */
    @Override
    public final void refresh() {
        if (wrappedPolicy != null) {
            wrappedPolicy.refresh();
        }
        try {
            listener.policyRefreshed();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
}

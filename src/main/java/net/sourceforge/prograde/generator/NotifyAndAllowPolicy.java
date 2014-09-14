/*
 * #%L
 * pro-grade
 * %%
 * Copyright (C) 2013 - 2014 Ondřej Lukáš, Josef Cacek
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package net.sourceforge.prograde.generator;

import java.security.AllPermission;
import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;

import net.sourceforge.prograde.policy.ProGradePolicy;

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

    /**
     * System property name for setting generated policy file path when the file is not specified in the constructor.
     */
    public static final String PROGRADE_USE_OWN_POLICY = "prograde.use.own.policy";

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
        if (policy != null) {
            wrappedPolicy = policy;
        } else if (Boolean.parseBoolean(SecurityActions.getSystemProperty(PROGRADE_USE_OWN_POLICY))) {
            wrappedPolicy = new ProGradePolicy();
        } else {
            wrappedPolicy = SecurityActions.getPolicy();
        }
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

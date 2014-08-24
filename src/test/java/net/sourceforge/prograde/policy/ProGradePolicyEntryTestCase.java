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
package net.sourceforge.prograde.policy;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.PropertyPermission;

import org.junit.Test;

/**
 * 
 * @author Ondrej Lukas
 */
public class ProGradePolicyEntryTestCase {

    private static final String TESTING_PRINCIPAL_CLASSNAME = ProGradeTestingPrincipal.class.getName();

    /*
     * test whether permission implies works right in ProgradePolicyEntryTestCase implies method
     */
    @Test
    public void testImpliesPermission() {
        ProtectionDomain pd = createPD();

        // test whether permission implies works right if permission implies other permission
        ProGradePolicyEntry ppe = createWithAllPermission();
        assertTrue(ppe.implies(pd, new PropertyPermission("java.home", "read")));

        // test whether permission implies works right for same permissions
        ppe = createWithJavaHomePropertyPermission();
        assertTrue(ppe.implies(pd, new PropertyPermission("java.home", "read")));

        // test whether permission implies works right if permission not implies another one
        assertFalse(ppe.implies(pd, new AllPermission()));

        // test whether permission implies works right if it has no permission
        ppe = new ProGradePolicyEntry(true, false);
        assertFalse(ppe.implies(pd, new PropertyPermission("java.home", "read")));

    }

    /*
     * tests whether neverImplies parameter works right in ProgradePolicyEntryTestCase implies method
     */
    @Test
    public void testImpliesNeverImplies() {
        ProtectionDomain pd = createPD();
        ProGradePolicyEntry ppe = createWithAllPermission();
        ppe.setNeverImplies(true);
        assertFalse(ppe.implies(pd, new PropertyPermission("java.home", "read")));
        ppe.setNeverImplies(false);
        assertTrue(ppe.implies(pd, new PropertyPermission("java.home", "read")));
    }

    /*
     * test whether CodeSource implies works right in ProgradePolicyEntryTestCase implies method
     */
    @Test
    public void testImpliesCodeSource() throws Exception {
        ProGradePolicyEntry ppe = createWithAllPermission();
        ppe.setCodeSource(new CodeSource(new URL("file:./path/to/file/-"), new Certificate[0]));

        // test whether PD with null CodeSource passes ProgradePolicyEntryTestCase implies method
        ProtectionDomain pd = createPD();
        assertTrue(ppe.implies(pd, new PropertyPermission("java.home", "read")));

        // test whether PD with same CodeSource passes ProgradePolicyEntryTestCase implies method
        pd = createPD(new CodeSource(new URL("file:./path/to/file/-"), new Certificate[0]));
        assertTrue(ppe.implies(pd, new PropertyPermission("java.home", "read")));

        // test whether PD with "wrong" CodeSource doesn't pass ProgradePolicyEntryTestCase implies method
        pd = createPD(new CodeSource(new URL("file:./wrong/path"), new Certificate[0]));
        assertFalse(ppe.implies(pd, new PropertyPermission("java.home", "read")));

        // test whether PD with implied CodeSource pass ProgradePolicyEntryTestCase implies method
        pd = createPD(new CodeSource(new URL("file:./path/to/file/which/is/implied"), new Certificate[0]));
        assertTrue(ppe.implies(pd, new PropertyPermission("java.home", "read")));
    }

    /*
     * test whether Principals implies works right in ProgradePolicyEntryTestCase implies method
     */
    @Test
    public void testImpliesPrincipals() {
        ProGradePolicyEntry ppe = createWithAllPermission();
        ppe.addPrincipal(new ProGradePrincipal(null, null, true, true));

        // test whether PD with no Principal doesn't pass ProgradePolicyEntryTestCase implies method
        ProtectionDomain pd = createPD();
        assertFalse(ppe.implies(pd, new PropertyPermission("java.home", "read")));

        // test whether PD with any Principal passes ProgradePolicyEntryTestCase implies method
        pd = createPDwithPrincipals(new Principal[] { new ProGradeTestingPrincipal("anyName") });
        assertTrue(ppe.implies(pd, new PropertyPermission("java.home", "read")));

        ppe.addPrincipal(new ProGradePrincipal(TESTING_PRINCIPAL_CLASSNAME, null, false, true));

        // test whether PD with any Principal passes ProgradePolicyEntryTestCase implies method
        pd = createPDwithPrincipals(new Principal[] { new ProGradeTestingPrincipal("anyName") });
        assertTrue(ppe.implies(pd, new PropertyPermission("java.home", "read")));

        ppe = createWithAllPermission();

        ppe.addPrincipal(new ProGradePrincipal(TESTING_PRINCIPAL_CLASSNAME, "A", false, false));

        // test whether PD with right Principal passes ProgradePolicyEntryTestCase implies method
        pd = createPDwithPrincipals(new Principal[] { new ProGradeTestingPrincipal("A") });
        assertTrue(ppe.implies(pd, new PropertyPermission("java.home", "read")));

        // test whether PD with wrong Principal doesn't pass ProgradePolicyEntryTestCase implies method
        pd = createPDwithPrincipals(new Principal[] { new ProGradeTestingPrincipal("B") });
        assertFalse(ppe.implies(pd, new PropertyPermission("java.home", "read")));

        // test whether PD with right and wrong Principal passes ProgradePolicyEntryTestCase implies method
        pd = createPDwithPrincipals(new Principal[] { new ProGradeTestingPrincipal("A"), new ProGradeTestingPrincipal("B") });
        assertTrue(ppe.implies(pd, new PropertyPermission("java.home", "read")));

        ppe.addPrincipal(new ProGradePrincipal(TESTING_PRINCIPAL_CLASSNAME, "B", false, false));

        // test whether PD with only one right Principal doesn't pass ProgradePolicyEntryTestCase implies method
        pd = createPDwithPrincipals(new Principal[] { new ProGradeTestingPrincipal("A") });
        assertFalse(ppe.implies(pd, new PropertyPermission("java.home", "read")));

        // test whether PD with both right Principals passes ProgradePolicyEntryTestCase implies method
        pd = createPDwithPrincipals(new Principal[] { new ProGradeTestingPrincipal("A"), new ProGradeTestingPrincipal("B") });
        assertTrue(ppe.implies(pd, new PropertyPermission("java.home", "read")));
    }

    private ProGradePolicyEntry createWithAllPermission() {
        ProGradePolicyEntry p = new ProGradePolicyEntry(true, false);
        p.addPermission(new AllPermission());
        return p;
    }

    private ProGradePolicyEntry createWithJavaHomePropertyPermission() {
        ProGradePolicyEntry p = new ProGradePolicyEntry(true, false);
        p.addPermission(new PropertyPermission("java.home", "read"));
        return p;
    }

    private ProtectionDomain createPD() {
        return createPD(null);
    }

    private ProtectionDomain createPD(CodeSource cs) {
        ProtectionDomain pd = new ProtectionDomain(cs, null);
        return pd;
    }

    private ProtectionDomain createPDwithPrincipals(Principal[] principals) {
        ProtectionDomain pd = new ProtectionDomain(null, null, null, principals);
        return pd;
    }
}

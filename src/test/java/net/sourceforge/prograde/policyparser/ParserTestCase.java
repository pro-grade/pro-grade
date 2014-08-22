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
package net.sourceforge.prograde.policyparser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.util.List;

import net.sourceforge.prograde.type.Priority;

import org.junit.Test;

/**
 * 
 * @author Ondrej Lukas
 */
public class ParserTestCase {

    @Test
    public void testParsingCompleteValidFile() {
        Parser parser = new Parser();
        ParsedPolicy parsedPolicy = null;
        try {
            parsedPolicy = parser
                    .parse(new File("src/test/java/net/sourceforge/prograde/policyparser/policyFiles/full.policy"));
        } catch (Exception ex) {
            fail("Valid policy file wasn't successfully parsed due to thrown exception: " + ex);
        }
        assertEquals("KeystorePasswordURL entry wasn't successfully parsed.", "pass.txt", parsedPolicy.getKeystorePasswordURL());
        assertEquals("Keystore entry (url part) wasn't successfully parsed.", "prograde.keystore", parsedPolicy.getKeystore()
                .getKeystoreURL());
        assertEquals("Keystore entry (type part) wasn't successfully parsed.", "type", parsedPolicy.getKeystore()
                .getKeystoreType());
        assertEquals("Keystore entry (provider part) wasn't successfully parsed.", "provider", parsedPolicy.getKeystore()
                .getKeystoreProvider());
        assertTrue("Priority entry wasn't successfully parsed.", Priority.GRANT == parsedPolicy.getPriority());

        List<ParsedPolicyEntry> grantEntries = parsedPolicy.getGrantEntries();
        assertTrue("Wrong number of grant entries was parsed.", grantEntries.size() == 2);
        boolean first = false;
        boolean second = false;
        for (ParsedPolicyEntry ppe : grantEntries) {
            if (ppe.getCodebase().equals("file:./One.jar")) {
                first = true;
                assertEquals("SignedBy entry wasn't successfully parsed.", "duke", ppe.getSignedBy());
                assertTrue("Wrong number of principal entries was parsed.", ppe.getPrincipals().size() == 2);

                boolean contained = false;
                for (ParsedPrincipal principal : ppe.getPrincipals()) {
                    if (principal.getPrincipalName().equals("user1")) {
                        assertEquals("Principal class name wasn't successfully parsed.", "sample.principal.SamplePrincipal",
                                principal.getPrincipalClass());
                        contained = true;
                        break;
                    }
                }
                if (!contained) {
                    fail("Principal with principal name user1 wasn' parsed.");
                }
                contained = false;
                for (ParsedPrincipal principal : ppe.getPrincipals()) {
                    if (principal.getPrincipalName().equals("user2")) {
                        assertEquals("Principal class name wasn't successfully parsed.", "sample.principal.NotSamplePrincipal",
                                principal.getPrincipalClass());
                        contained = true;
                        break;
                    }
                }
                if (!contained) {
                    fail("Principal with principal name user2 wasn' parsed.");
                }

                assertTrue("Wrong number of permission was parsed.", ppe.getPermissions().size() == 2);
                contained = false;
                for (ParsedPermission perm : ppe.getPermissions()) {
                    if (perm.getPermissionName().equals("java.home")) {
                        assertEquals("Permission type wasn't successfully parsed.", "java.util.PropertyPermission",
                                perm.getPermissionType());
                        assertEquals("Permission actions weren't successfully parsed.", "read,write", perm.getActions());
                        assertEquals("Permission signedBy wasn't successfully parsed.", "adam", perm.getSignedBy());
                        contained = true;
                        break;
                    }
                }
                if (!contained) {
                    fail("PropertyPermission with name \"java.home\" wasn' parsed.");
                }
                contained = false;
                for (ParsedPermission perm : ppe.getPermissions()) {
                    if (perm.getPermissionName().equals("user.home")) {
                        assertEquals("Permission type wasn't successfully parsed.", "java.util.PropertyPermission",
                                perm.getPermissionType());
                        assertEquals("Permission actions weren't successfully parsed.", "read", perm.getActions());
                        assertEquals("Permission signedBy wasn't successfully parsed.", "bob", perm.getSignedBy());
                        contained = true;
                        break;
                    }
                }
                if (!contained) {
                    fail("PropertyPermission with name \"user.home\" wasn' parsed.");
                }

            } else {
                if (ppe.getCodebase().equals("file:./Two.jar")) {
                    second = true;
                    assertTrue("Wrong number of principal entries was parsed.", ppe.getPrincipals().isEmpty());
                    assertNull("Wrong number of signedBy entries was parsed.", ppe.getSignedBy());
                    assertTrue("Wrong number of permission entries was parsed.", ppe.getPermissions().size() == 1);
                    for (ParsedPermission perm : ppe.getPermissions()) {
                        assertEquals("Permission name wasn't successfully parsed.", "java.security.AllPermission",
                                perm.getPermissionType());
                        assertNull("Permission type wasn't defined but isn't null.", perm.getPermissionName());
                        assertNull("Permission action wasn't defined but isn't null.", perm.getActions());
                        assertNull("Permission signedBy wasn't defined but isn't null.", perm.getSignedBy());
                    }
                } else {
                    fail("Codebase in grant entry wasn't successfully parsed.");
                }
            }
        }
        if (!first || !second) {
            fail("Two different entries were in policy file but only one of them was parsed but saved twice.");
        }

        List<ParsedPolicyEntry> denyEntries = parsedPolicy.getDenyEntries();
        assertTrue("Wrong number of deny entries was parsed.", denyEntries.size() == 1);
        for (ParsedPolicyEntry ppe : denyEntries) {
            assertTrue("Principal wasn't defined but isn't empty.", ppe.getPrincipals().isEmpty());
            assertNull("SignedBy wasn't defined but isn't null.", ppe.getSignedBy());
            assertNull("Codebase wasn't defined but isn't null.", ppe.getCodebase());
            assertTrue("Wrong number of permission entries was parsed.", ppe.getPermissions().size() == 1);
            for (ParsedPermission perm : ppe.getPermissions()) {
                assertEquals("Permission name wasn't successfully parsed.", "javax.security.auth.AuthPermission",
                        perm.getPermissionType());
                assertEquals("Permission type wasn't defined but isn't null.", "doAsPrivileged", perm.getPermissionName());
                assertNull("Permission action wasn't defined but isn't null.", perm.getActions());
                assertNull("Permission signedBy wasn't defined but isn't null.", perm.getSignedBy());
            }
        }
    }

    @Test
    public void testKeystoreAndKeystorePassTwiceAndNotPriority() {
        Parser parser = new Parser();
        ParsedPolicy parsedPolicy = null;
        try {
            parsedPolicy = parser.parse(new File("src/test/java/net/sourceforge/prograde/policyparser/policyFiles/"
                    + "keystoreAndKeystorePassTwiceAndNotPriority.policy"));
        } catch (Exception ex) {
            fail("Valid policy file wasn't successfully parsed due to thrown exception: " + ex);
        }
        assertEquals("It doesn't contain right KeystorePasswordURL.", "rightpass.txt", parsedPolicy.getKeystorePasswordURL());
        assertEquals("It doesn't contain right Keystore entry.", "right.keystore", parsedPolicy.getKeystore().getKeystoreURL());
        assertNull("Priority wasn't defined. It should be null.", parsedPolicy.getPriority());
    }

    @Test
    public void testCodebaseTwice() {
        Parser parser = new Parser();
        try {
            parser.parse(new File("src/test/java/net/sourceforge/prograde/policyparser/policyFiles/codebaseTwice.policy"));
            fail("There was definition of two codebase in one entry, it should throw Exception, but is passed.");
        } catch (Exception ex) {
        }
    }

    @Test
    public void testSignedByTwice() {
        Parser parser = new Parser();
        try {
            parser.parse(new File("src/test/java/net/sourceforge/prograde/policyparser/policyFiles/signedByTwice.policy"));
            fail("There was definition of two codebase in one entry, it should throw Exception, but is passed.");
        } catch (Exception ex) {
        }
    }

    @Test
    public void testAliasPrincipal() {
        Parser parser = new Parser();
        ParsedPolicy parsedPolicy = null;
        try {
            parsedPolicy = parser.parse(new File(
                    "src/test/java/net/sourceforge/prograde/policyparser/policyFiles/aliasPrincipal.policy"));
        } catch (Exception ex) {
            fail("Valid policy file wasn't successfully parsed due to thrown exception: " + ex);
        }
        List<ParsedPolicyEntry> grantEntries = parsedPolicy.getGrantEntries();
        assertTrue("Wrong number of grant entries was parsed.", grantEntries.size() == 1);
        List<ParsedPrincipal> principals = grantEntries.get(0).getPrincipals();
        assertTrue("Wrong number of principal entries was parsed.", principals.size() == 1);
        ParsedPrincipal principal = principals.get(0);
        assertTrue("hasAlias return false but it has alias.", principal.hasAlias());
        assertEquals("Alias wasn't parsed right", "alias", principal.getAlias());
    }

    @Test
    public void testTwoWildCardsPrincipal() {
        Parser parser = new Parser();
        ParsedPolicy parsedPolicy = null;
        try {
            parsedPolicy = parser.parse(new File(
                    "src/test/java/net/sourceforge/prograde/policyparser/policyFiles/twoWildCardsPrincipal.policy"));
        } catch (Exception ex) {
            fail("Valid policy file wasn't successfully parsed due to thrown exception: " + ex);
        }
        List<ParsedPolicyEntry> grantEntries = parsedPolicy.getGrantEntries();
        assertTrue("Wrong number of grant entries was parsed.", grantEntries.size() == 1);
        List<ParsedPrincipal> principals = grantEntries.get(0).getPrincipals();
        assertTrue("Wrong number of principal entries was parsed.", principals.size() == 1);
        ParsedPrincipal principal = principals.get(0);
        assertTrue("hasClassWildcard return false but it has this wildcard.", principal.hasClassWildcard());
        assertTrue("hasNameWildcard return false but it has this wildcard.", principal.hasNameWildcard());
    }

    @Test
    public void testOneWildCardPrincipal() {
        Parser parser = new Parser();
        ParsedPolicy parsedPolicy = null;
        try {
            parsedPolicy = parser.parse(new File(
                    "src/test/java/net/sourceforge/prograde/policyparser/policyFiles/oneWildCardPrincipal.policy"));
        } catch (Exception ex) {
            fail("Valid policy file wasn't successfully parsed due to thrown exception: " + ex);
        }
        List<ParsedPolicyEntry> grantEntries = parsedPolicy.getGrantEntries();
        assertTrue("Wrong number of grant entries was parsed.", grantEntries.size() == 1);
        List<ParsedPrincipal> principals = grantEntries.get(0).getPrincipals();
        assertTrue("Wrong number of principal entries was parsed.", principals.size() == 1);
        ParsedPrincipal principal = principals.get(0);
        assertTrue("hasNameWildcard return false but it has this wildcard.", principal.hasNameWildcard());
        assertEquals("Principal class name wasn't successfully parsed.", "sample.principal.SamplePrincipal",
                principal.getPrincipalClass());
    }
}

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

import java.awt.AWTPermission;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilePermission;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.SerializablePermission;
import java.lang.reflect.Constructor;
import java.lang.reflect.ReflectPermission;
import java.net.NetPermission;
import java.net.SocketPermission;
import java.net.URL;
import java.security.AccessControlException;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.KeyStore;
import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.security.SecurityPermission;
import java.security.UnresolvedPermission;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.PropertyPermission;
import java.util.regex.Pattern;

import javax.security.auth.AuthPermission;
import javax.security.auth.x500.X500Principal;

import net.sourceforge.prograde.debug.ProGradePolicyDebugger;
import net.sourceforge.prograde.policyparser.ParsedKeystoreEntry;
import net.sourceforge.prograde.policyparser.ParsedPermission;
import net.sourceforge.prograde.policyparser.ParsedPolicy;
import net.sourceforge.prograde.policyparser.ParsedPolicyEntry;
import net.sourceforge.prograde.policyparser.ParsedPrincipal;
import net.sourceforge.prograde.policyparser.Parser;
import net.sourceforge.prograde.type.Priority;

/**
 * Policy file class which works with grant and deny policy rules in policy file.
 * 
 * @author Ondrej Lukas
 */
public class ProGradePolicy extends Policy {

    private Priority priority; // true for grant, false for deny
    private List<ProGradePolicyEntry> allGrantEntries;
    private List<ProGradePolicyEntry> allDenyEntries;
    private final boolean debug;
    private final boolean expandProperties;
    private final File file;
    private final boolean skipDefaultPolicies;

    /**
     * Constructor of ProgradePolicyFile.
     */
    public ProGradePolicy() {
        String debugProperty = null;
        try {
            debugProperty = SecurityActions.getSystemProperty("java.security.debug");
        } catch (AccessControlException ace) {
            System.err.println("Unable to check if policy debugging is enabled.");
            ace.printStackTrace();
        }
        boolean debugPolicy = false;
        if (debugProperty != null) {
            String[] splitDebugProperty = debugProperty.split(",");
            for (int i = 0; i < splitDebugProperty.length; i++) {
                String split = splitDebugProperty[i].trim();
                split = split.replaceAll("\"", "");
                // only these types of debug are connected with policy
                if (split.equals("all") || split.equals("policy")) {
                    debugPolicy = true;
                    break;
                }
            }
        }
        debug = debugPolicy;
        expandProperties = Boolean.parseBoolean(SecurityActions.getSecurityProperty("policy.expandProperties"));
        String policyFile = SecurityActions.getSystemProperty("java.security.policy");
        if (policyFile != null) {
            skipDefaultPolicies = policyFile.startsWith("=");
            if (skipDefaultPolicies) {
                policyFile = policyFile.substring(1);
            }
            file = new File(policyFile);
        } else {
            skipDefaultPolicies = false;
            file = null;
        }
        refresh();
    }

    /**
     * Method which loads policy data from policy file.
     */
    @Override
    public void refresh() {
        FileReader fr = null;
        if (file != null) {
            try {
                fr = new FileReader(file);
            } catch (Exception e) {
                System.err.println("Unable to read policy file " + file + ": " + e.getMessage());
            }
        }
        loadPolicy(fr, skipDefaultPolicies);
    }

    protected void loadPolicy(final Reader reader, final boolean exclusiveMode) {
        final List<ParsedPolicy> parsedPolicies = new ArrayList<ParsedPolicy>();

        final List<ProGradePolicyEntry> newGrantEntries = new ArrayList<ProGradePolicyEntry>();
        final List<ProGradePolicyEntry> newDenyEntries = new ArrayList<ProGradePolicyEntry>();
        Priority newPriority = null;
        try {
            if (reader != null) {
                try {
                    parsedPolicies.add(new Parser(debug).parse(reader));
                } catch (Exception ex) {
                    System.err.println("Unbale to parse policy. Exception message: " + ex.getMessage());
                } finally {
                    try {
                        reader.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }

            // parse policies specified in java.security when not in exclusive mode (==)
            if (!exclusiveMode) {
                try {
                    parsedPolicies.addAll(getJavaPolicies());
                } catch (Exception ex) {
                    System.err.println("Static policy wasn't successfully loaded! Exception message: " + ex.getMessage());
                }
            }

            if (!exclusiveMode && parsedPolicies.isEmpty()) {
                try {
                    initializeStaticPolicy(newGrantEntries);
                } catch (Exception ex) {
                    System.err.println("Static policy wasn't successfully loaded! Exception message: " + ex.getMessage());
                }

            } else {
                try {
                    // initializePolicy
                    if (parsedPolicies.isEmpty()) {
                        throw new Exception("Policy wasn't initialized!");
                    }
                    // set priority - priority is set according first loaded policy
                    newPriority = null;
                    for (ParsedPolicy pp : parsedPolicies) {
                        newPriority = pp.getPriority();
                        if (newPriority != null)
                            break;
                    }
                    if (newPriority == null)
                        newPriority = Priority.DEFAULT;

                    for (ParsedPolicy p : parsedPolicies) {
                        KeyStore keystore = null;
                        try {
                            keystore = createKeystore(p.getKeystore(), p.getKeystorePasswordURL(), file);
                        } catch (Exception ex) {
                            System.err.println("Keystore wasn't successfully initialized! Exception message: "
                                    + ex.getMessage());
                        }

                        // add grant and deny policy entry
                        addParsedPolicyEntries(p.getGrantEntries(), newGrantEntries, keystore, true);
                        addParsedPolicyEntries(p.getDenyEntries(), newDenyEntries, keystore, false);
                    }
                } catch (Exception ex) {
                    System.err.println("Policy wasn't successfully initialized! Exception message: " + ex.getMessage());
                }
            }
        } finally {
            allGrantEntries = newGrantEntries;
            allDenyEntries = newDenyEntries;
            priority = newPriority;
        }

    }

    /**
     * Private method which adds parsedEntries to entries.
     * 
     * @param parsedEntries parsed entries from policy file which will be added to entries
     * @param entries entries will add parsed entries to themselves
     * @param keystore KeyStore which is used by this policy file
     * @param grant true for priority grant, false for priority deny
     * @throws Exception when there was any problem during adding entries to policy
     */
    private void addParsedPolicyEntries(List<ParsedPolicyEntry> parsedEntries, List<ProGradePolicyEntry> entries,
            KeyStore keystore, boolean grant) throws Exception {
        for (ParsedPolicyEntry p : parsedEntries) {
            try {
                entries.add(initializePolicyEntry(p, keystore, grant));
            } catch (Exception e) {
                System.err.println("Unable to initialize policy entry: " + e.getMessage());
            }
        }
    }

    /**
     * Private method for initializing one policy entry.
     * 
     * @param parsedEntry parsed entry using for creating new entry ProgradePolicyEntry
     * @param keystore KeyStore which is used by this policy file
     * @param grant true for priority grant, false for priority deny
     * @return ProgradePolicyEntry which represents this parsedEntry
     * @throws Exception when there was any problem during initializing of policy entry
     */
    private ProGradePolicyEntry initializePolicyEntry(ParsedPolicyEntry parsedEntry, KeyStore keystore, boolean grant)
            throws Exception {
        ProGradePolicyEntry entry = new ProGradePolicyEntry(grant, debug);

        // codesource
        if (parsedEntry.getCodebase() != null || parsedEntry.getSignedBy() != null) {
            CodeSource cs = createCodeSource(parsedEntry, keystore);
            if (cs != null) {
                entry.setCodeSource(cs);
            } else {
                // it happens if there is signedBy which isn't contain in keystore
                entry.setNeverImplies(true);
                // any next isn't needed because entry will never implies anything
                return entry;
            }
        }

        // principals
        for (ParsedPrincipal p : parsedEntry.getPrincipals()) {
            if (p.hasAlias()) {
                String principal = gainPrincipalFromAlias(expandStringWithProperty(p.getAlias()), keystore);
                if (principal != null) {
                    entry.addPrincipal(new ProGradePrincipal("javax.security.auth.x500.X500Principal", principal, false, false));
                } else {
                    // it happens if there is alias which isn't contain in keystore
                    entry.setNeverImplies(true);
                    // any next isn't needed because entry will never implies anything
                    return entry;
                }
            } else {
                entry.addPrincipal(new ProGradePrincipal(p.getPrincipalClass(), expandStringWithProperty(p.getPrincipalName()),
                        p.hasClassWildcard(), p.hasNameWildcard()));
            }
        }

        // permissions
        for (ParsedPermission p : parsedEntry.getPermissions()) {
            Permission perm = createPermission(p, keystore);
            if (perm != null) {
                entry.addPermission(perm);
            }
        }

        return entry;
    }

    /**
     * Method for determining whether this ProgradePolicyEntry implies given permission.
     * 
     * @param protectionDomain active ProtectionDomain to test
     * @param permission Permission which need to be determined
     * @return true if ProgradePolicyFile implies given Permission, false otherwise
     */
    @Override
    public boolean implies(ProtectionDomain protectionDomain, Permission permission) {

        // this should never happen
        if (protectionDomain == null) {
            return false;
        }

        // everything is granted in this case
        if (protectionDomain.getCodeSource() == null) {
            return true;
        }

        if (Priority.GRANT.equals(priority)) { // branch for grant priority
            if (debug) {
                ProGradePolicyDebugger.log("Searching for granting for permission: " + permission + " ...");
            }
            if (grantEntriesImplies(protectionDomain, permission)) {
                if (debug) {
                    ProGradePolicyDebugger.log("Granting permission found, grant access.");
                }
                return true;
            } else {
                if (debug) {
                    ProGradePolicyDebugger.log("Granting permission wasn't found, searching for denying...");
                }
                boolean toReturn = !denyEntriesImplies(protectionDomain, permission);
                if (debug) {
                    if (toReturn) {
                        ProGradePolicyDebugger.log("Denying permission wasn't found, grant access.");
                    } else {
                        ProGradePolicyDebugger.log("Denying permission found, deny access.");
                    }
                }
                return toReturn;
            }
        } else { // branch for deny priority
            if (debug) {
                ProGradePolicyDebugger.log("Searching for denying for permission: " + permission + " ...");
            }
            if (denyEntriesImplies(protectionDomain, permission)) {
                if (debug) {
                    ProGradePolicyDebugger.log("Denying permission found, deny access.");
                }
                return false;
            } else {
                if (debug) {
                    ProGradePolicyDebugger.log("Denying permission wasn't found, searching for granting...");
                }
                boolean toReturn = grantEntriesImplies(protectionDomain, permission);
                if (debug) {
                    if (toReturn) {
                        ProGradePolicyDebugger.log("Granting permission found, grant access.");
                    } else {
                        ProGradePolicyDebugger.log("Granting permission wasn't found, deny access.");
                    }
                }
                return toReturn;
            }
        }
    }

    /**
     * Private method for determining whether grant entries of ProgradePolicyFile imply given Permission.
     * 
     * @param domain active ProtectionDomain to test
     * @param permission Permission which need to be determined
     * @return true if grant entries of this ProgradePolicyFile grant given Permission, false otherwise
     */
    private boolean grantEntriesImplies(ProtectionDomain domain, Permission permission) {
        return entriesImplyPermission(allGrantEntries, domain, permission);
    }

    /**
     * Private method for determining whether deny entries of ProgradePolicyFile imply given Permission which means denying it.
     * 
     * @param domain active ProtectionDomain to test
     * @param permission Permission which need to be determined
     * @return true if deny entries of this ProgradePolicyFile deny given Permission, false otherwise
     */
    private boolean denyEntriesImplies(ProtectionDomain domain, Permission permission) {
        return entriesImplyPermission(allDenyEntries, domain, permission);
    }

    /**
     * Private method for determining whether grant or deny entries of ProgradePolicyFile imply given Permission.
     * 
     * @param domain active ProtectionDomain to test
     * @param permission Permission which need to be determined
     * 
     * @return true if grant or deny entries of this ProgradePolicyFile imply given Permission, false otherwise
     */
    private boolean entriesImplyPermission(List<ProGradePolicyEntry> policyEntriesList, ProtectionDomain domain,
            Permission permission) {
        for (ProGradePolicyEntry entry : policyEntriesList) {
            if (entry.implies(domain, permission)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Private method for creating new Permission object from ParsedPermission.
     * 
     * @param p ParsedPermission with informations about Permission.
     * @param keystore KeyStore which is used by this policy file
     * @return new created Permission or null if Permission doesn't exist or doesn't be created.
     * @throws Exception when there was any problem during creating Permission
     */
    private Permission createPermission(ParsedPermission p, KeyStore keystore) throws Exception {
        if (p == null) {
            return null;
        }

        String permissionName = expandStringWithProperty(p.getPermissionName());
        String actions = expandStringWithProperty(p.getActions());

        Class<?> clazz;
        try {
            clazz = Class.forName(p.getPermissionType());
        } catch (ClassNotFoundException ex) {
            Certificate[] certificates = getCertificates(expandStringWithProperty(p.getSignedBy()), keystore);
            if (p.getSignedBy() != null && certificates == null) {
                if (debug) {
                    ProGradePolicyDebugger.log("Permission with signedBy " + p.getSignedBy()
                            + " is ignored. Certificate wasn't successfully found or loaded " + "from keystore");
                }
                return null;
            }
            return new UnresolvedPermission(p.getPermissionType(), permissionName, actions, certificates);
        }

        try {
            if (clazz.equals(FilePermission.class)) {
                return new FilePermission(permissionName, actions);
            } else if (clazz.equals(SocketPermission.class)) {
                return new SocketPermission(permissionName, actions);
            } else if (clazz.equals(PropertyPermission.class)) {
                return new PropertyPermission(permissionName, actions);
            } else if (clazz.equals(RuntimePermission.class)) {
                return new RuntimePermission(permissionName, actions);
            } else if (clazz.equals(AWTPermission.class)) {
                return new AWTPermission(permissionName, actions);
            } else if (clazz.equals(NetPermission.class)) {
                return new NetPermission(permissionName, actions);
            } else if (clazz.equals(ReflectPermission.class)) {
                return new ReflectPermission(permissionName, actions);
            } else if (clazz.equals(SerializablePermission.class)) {
                return new SerializablePermission(permissionName, actions);
            } else if (clazz.equals(SecurityPermission.class)) {
                return new SecurityPermission(permissionName, actions);
            } else if (clazz.equals(AllPermission.class)) {
                return new AllPermission(permissionName, actions);
            } else if (clazz.equals(AuthPermission.class)) {
                return new AuthPermission(permissionName, actions);
            }
        } catch (IllegalArgumentException ex) {
            System.err.println("IllegalArgumentException in permission: [" + p.getPermissionType() + ", " + permissionName
                    + ", " + actions + "]");
            return null;
        }

        // check signedBy permission for classes which weren't loaded by boostrap classloader
        // in some java clazz.getClassLoader() returns null for boostrap classloader
        if (clazz.getClassLoader() != null) {
            // another check whether clazz.getClassLoader() isn't bootstrap classloader
            if (!clazz.getClassLoader().equals(clazz.getClassLoader().getParent())) {
                if (p.getSignedBy() != null) {
                    Certificate[] signers = (Certificate[]) clazz.getSigners();
                    if (signers == null) {
                        return null;
                    } else {
                        Certificate[] certificates = getCertificates(expandStringWithProperty(p.getSignedBy()), keystore);
                        if (certificates == null) {
                            return null;
                        } else {
                            for (int i = 0; i < certificates.length; i++) {
                                Certificate certificate = certificates[i];
                                boolean contain = false;
                                for (int j = 0; j < signers.length; j++) {
                                    Certificate signedCertificate = signers[j];
                                    if (certificate.equals(signedCertificate)) {
                                        contain = true;
                                        break;
                                    }
                                }
                                if (!contain) {
                                    return null;
                                }
                            }
                        }
                    }
                }
            }
        }

        try {
            Constructor<?> c = clazz.getConstructor(String.class, String.class);
            return (Permission) c.newInstance(new Object[] { permissionName, actions });
        } catch (NoSuchMethodException ex1) {
            try {
                Constructor<?> c = clazz.getConstructor(String.class);
                return (Permission) c.newInstance(new Object[] { permissionName });
            } catch (NoSuchMethodException ex2) {
                Constructor<?> c = clazz.getConstructor();
                return (Permission) c.newInstance(new Object[] {});
            }
        }
    }

    /**
     * Private method for expanding String which contains any property.
     * 
     * @param s String for expanding
     * @return expanded String
     * @throws Exception when any ends without '}' or contains inner property expansion
     */
    private String expandStringWithProperty(String s) throws Exception {
        // if expandProperties is false, don't expand property
        if (!expandProperties) {
            return s;
        }
        // if string doesn't contain property, returns original string
        if (s == null || s.indexOf("${") == -1) {
            return s;
        }
        String toReturn = "";
        String[] split = s.split(Pattern.quote("${"));
        toReturn += split[0];
        for (int i = 1; i < split.length; i++) {
            String part = split[i];
            // don't expand ${{...}}
            if (part.startsWith("{")) {
                toReturn += ("${" + part);
                continue;
            }
            String[] splitPart = part.split("}", 2);
            if (splitPart.length < 2) {
                throw new Exception("ER001: Expand property without end } or inner property expansion!");
            } else {
                // add expanded property
                // ${/} = file.separator
                if (splitPart[0].equals("/")) {
                    toReturn += File.separator;
                } else {
                    toReturn += SecurityActions.getSystemProperty(splitPart[0]);
                }
                toReturn += splitPart[1];
            }
        }
        return toReturn;
    }

    /**
     * Private method for creating new CodeSource object from ParsedEntry.
     * 
     * @param parsedEntry ParsedEntry with informations about CodeSource
     * @param keystore KeyStore which is used by this policy file
     * @return new created CodeSource
     * @throws Exception when there was any problem during creating CodeSource
     */
    private CodeSource createCodeSource(ParsedPolicyEntry parsedEntry, KeyStore keystore) throws Exception {
        String parsedCodebase = expandStringWithProperty(parsedEntry.getCodebase());
        String parsedCertificates = expandStringWithProperty(parsedEntry.getSignedBy());
        String[] splitCertificates = new String[0];
        if (parsedCertificates != null) {
            splitCertificates = parsedCertificates.split(",");
        }
        if (splitCertificates.length > 0 && keystore == null) {
            throw new Exception("ER002: Keystore must be defined if signedBy is used");
        }

        List<Certificate> certList = new ArrayList<Certificate>();

        for (int i = 0; i < splitCertificates.length; i++) {
            Certificate certificate = keystore.getCertificate(splitCertificates[i]);
            if (certificate != null) {
                certList.add(certificate);
            } else {
                // return null to indicate that it never implies any permission
                return null;
            }
        }
        Certificate[] certificates;
        if (certList.isEmpty()) {
            certificates = null;
        } else {
            certificates = new Certificate[certList.size()];
            certList.toArray(certificates);
        }

        URL url;
        if (parsedCodebase == null) {
            url = null;
        } else {
            url = new URL(parsedCodebase);
        }
        CodeSource cs = new CodeSource(adaptURL(url), certificates);
        return cs;
    }

    /**
     * Private method for adapting URL for using of this ProgradePolicyFile.
     * 
     * @param url URL for adapting
     * @return adapted URL
     * @throws Exception when there was any problem during adapting URL
     */
    private URL adaptURL(URL url) throws Exception {
        if (url != null && url.getProtocol().equals("file")) {
            String host = url.getHost();
            // if it is local file
            if (host == null || host.equals("") || host.equals("~") || host.equalsIgnoreCase("localhost")) {
                // make path readable for specific OS
                String path = url.getFile().replace('/', File.separatorChar);

                path = encodeSpecialCharacters(path);

                path = path.replace(File.separatorChar, '/');

                return new URL("file", "", path);
            }
        }
        return url;
    }

    /**
     * Private method for creating KeyStore object from ParsedKeystoreEntry and other information from policy file.
     * 
     * @param parsedKeystoreEntry parsedKeystoreEntry containing information about keystore
     * @param keystorePasswordURL URL to file which contain password for given keystore
     * @param policyFile used policy file
     * @return new created KeyStore
     * @throws Exception when there was any problem during creating KeyStore
     */
    private KeyStore createKeystore(ParsedKeystoreEntry parsedKeystoreEntry, String keystorePasswordURL, File policyFile)
            throws Exception {
        if (parsedKeystoreEntry == null) {
            return null;
        }
        KeyStore toReturn;
        String keystoreURL = expandStringWithProperty(parsedKeystoreEntry.getKeystoreURL());
        String keystoreType = expandStringWithProperty(parsedKeystoreEntry.getKeystoreType());
        String keystoreProvider = expandStringWithProperty(parsedKeystoreEntry.getKeystoreProvider());

        if (keystoreURL == null) {
            throw new Exception("ER003: Null keystore url!");
        }

        if (keystoreType == null) {
            keystoreType = KeyStore.getDefaultType();
        }

        if (keystoreProvider == null) {
            toReturn = KeyStore.getInstance(keystoreType);
        } else {
            toReturn = KeyStore.getInstance(keystoreType, keystoreProvider);
        }

        char[] keystorePassword = null;
        if (keystorePasswordURL != null) {
            keystorePassword = readKeystorePassword(expandStringWithProperty(keystorePasswordURL), policyFile);
        }

        // try relative path to policy file
        String path = getPolicyFileHome(policyFile);
        File f = null;
        if (path != null) {
            f = new File(path, keystoreURL);
        }
        if (f == null || !f.exists()) {
            // try absoluth path
            f = new File(keystoreURL);
            if (!f.exists()) {
                throw new Exception("ER004: KeyStore doesn't exists!");
            }
        }

        FileInputStream fis = null;
        try {
            fis = new FileInputStream(f);
            toReturn.load(fis, keystorePassword);
        } finally {
            if (fis != null) {
                fis.close();
            }
        }

        return toReturn;
    }

    /**
     * Private method for reading password for keystore from file.
     * 
     * @param keystorePasswordURL URL to file which contain password for keystore
     * @param policyFile used policy file
     * @return password for keystore
     * @throws Exception when there was any problem during reading keystore password
     */
    private char[] readKeystorePassword(String keystorePasswordURL, File policyFile) throws Exception {
        // try relative path to policy file
        File f = new File(getPolicyFileHome(policyFile), keystorePasswordURL);
        if (!f.exists()) {
            // try absoluth path
            f = new File(keystorePasswordURL);
            if (!f.exists()) {
                throw new Exception("ER005: File on keystorePasswordURL doesn't exists!");
            }
        }
        Reader reader = new FileReader(f);
        StringBuilder sb = new StringBuilder();
        char buffer[] = new char[64];
        int len;
        while ((len = reader.read(buffer)) > 0) {
            sb.append(buffer, 0, len);
        }
        reader.close();
        return sb.toString().trim().toCharArray();
    }

    /**
     * Private method for gaining X500Principal from keystore according its alias.
     * 
     * @param alias alias of principal
     * @param keystore KeyStore which is used by this policy file
     * @return name of gained X500Principal
     * @throws Exception when there was any problem during gaining Principal
     */
    private String gainPrincipalFromAlias(String alias, KeyStore keystore) throws Exception {
        if (keystore == null) {
            return null;
        }
        if (!keystore.containsAlias(alias)) {
            return null;
        }

        Certificate certificate = keystore.getCertificate(alias);
        if (certificate == null || !(certificate instanceof X509Certificate)) {
            return null;
        }

        X509Certificate x509Certificate = (X509Certificate) certificate;
        X500Principal principal = new X500Principal(x509Certificate.getSubjectX500Principal().toString());
        return principal.getName();
    }

    /**
     * Private method for gaining absolute path of folder with policy file .
     * 
     * @param file file with policy
     * @return absolute path for folder with policy file or null if file doesn't exist
     */
    private String getPolicyFileHome(File file) {
        if (file == null || !file.exists()) {
            return null;
        }
        return file.getAbsoluteFile().getParent();
    }

    /**
     * Private method for gaining and parsing all policies defined in java.security file.
     * 
     * @return Parsed policies in list of ParsedPolicy
     */
    private List<ParsedPolicy> getJavaPolicies() {
        List<ParsedPolicy> list = new ArrayList<ParsedPolicy>();

        int counter = 1;
        String policyUrl = null;
        while ((policyUrl = SecurityActions.getSecurityProperty("policy.url." + counter)) != null) {
            try {
                policyUrl = expandStringWithProperty(policyUrl);
            } catch (Exception ex) {
                System.err.println("Expanding filepath in policy policy.url." + counter + "=" + policyUrl
                        + " failed. Exception message: " + ex.getMessage());
                counter++;
                continue;
            }
            ParsedPolicy p = null;
            InputStreamReader reader = null;
            try {
                reader = new InputStreamReader(new URL(policyUrl).openStream(), "UTF-8");
                p = new Parser(debug).parse(reader);
                if (p != null) {
                    list.add(p);
                } else {
                    System.err.println("Parsed policy policy.url." + counter + "=" + policyUrl + " is null");
                }
            } catch (Exception ex) {
                System.err.println("Policy policy.url." + counter + "=" + policyUrl
                        + " wasn't successfully parsed. Exception message: " + ex.getMessage());
            } finally {
                if (reader != null) {
                    try {
                        reader.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
            counter++;
        }

        return list;
    }

    /**
     * Private method for initializing static policy.
     * 
     * @throws Exception when there was any problem during initializing static policy
     */
    private void initializeStaticPolicy(List<ProGradePolicyEntry> grantEntriesList) throws Exception {

        // grant codeBase "file:${{java.ext.dirs}}/*" {
        // permission java.security.AllPermission;
        // };
        ProGradePolicyEntry p1 = new ProGradePolicyEntry(true, debug);
        Certificate[] certificates = null;
        URL url = new URL(expandStringWithProperty("file:${{java.ext.dirs}}/*"));
        CodeSource cs = new CodeSource(adaptURL(url), certificates);
        p1.setCodeSource(cs);
        p1.addPermission(new AllPermission());
        grantEntriesList.add(p1);

        // grant {
        // permission java.lang.RuntimePermission "stopThread";
        // permission java.net.SocketPermission "localhost:1024-", "listen";
        // permission java.util.PropertyPermission "java.version", "read";
        // permission java.util.PropertyPermission "java.vendor", "read";
        // permission java.util.PropertyPermission "java.vendor.url", "read";
        // permission java.util.PropertyPermission "java.class.version", "read";
        // permission java.util.PropertyPermission "os.name", "read";
        // permission java.util.PropertyPermission "os.version", "read";
        // permission java.util.PropertyPermission "os.arch", "read";
        // permission java.util.PropertyPermission "file.separator", "read";
        // permission java.util.PropertyPermission "path.separator", "read";
        // permission java.util.PropertyPermission "line.separator", "read";
        // permission java.util.PropertyPermission "java.specification.version", "read";
        // permission java.util.PropertyPermission "java.specification.vendor", "read";
        // permission java.util.PropertyPermission "java.specification.name", "read";
        // permission java.util.PropertyPermission "java.vm.specification.version", "read";
        // permission java.util.PropertyPermission "java.vm.specification.vendor", "read";
        // permission java.util.PropertyPermission "java.vm.specification.name", "read";
        // permission java.util.PropertyPermission "java.vm.version", "read";
        // permission java.util.PropertyPermission "java.vm.vendor", "read";
        // permission java.util.PropertyPermission "java.vm.name", "read";
        // };
        ProGradePolicyEntry p2 = new ProGradePolicyEntry(true, debug);
        p2.addPermission(new RuntimePermission("stopThread"));
        p2.addPermission(new SocketPermission("localhost:1024-", "listen"));
        p2.addPermission(new PropertyPermission("java.version", "read"));
        p2.addPermission(new PropertyPermission("java.vendor", "read"));
        p2.addPermission(new PropertyPermission("java.vendor.url", "read"));
        p2.addPermission(new PropertyPermission("java.class.version", "read"));
        p2.addPermission(new PropertyPermission("os.name", "read"));
        p2.addPermission(new PropertyPermission("os.version", "read"));
        p2.addPermission(new PropertyPermission("os.arch", "read"));
        p2.addPermission(new PropertyPermission("file.separator", "read"));
        p2.addPermission(new PropertyPermission("path.separator", "read"));
        p2.addPermission(new PropertyPermission("line.separator", "read"));
        p2.addPermission(new PropertyPermission("java.specification.version", "read"));
        p2.addPermission(new PropertyPermission("java.specification.vendor", "read"));
        p2.addPermission(new PropertyPermission("java.specification.name", "read"));
        p2.addPermission(new PropertyPermission("java.vm.specification.version", "read"));
        p2.addPermission(new PropertyPermission("java.vm.specification.vendor", "read"));
        p2.addPermission(new PropertyPermission("java.vm.specification.name", "read"));
        p2.addPermission(new PropertyPermission("java.vm.version", "read"));
        p2.addPermission(new PropertyPermission("java.vm.vendor", "read"));
        p2.addPermission(new PropertyPermission("java.vm.name", "read"));
        grantEntriesList.add(p2);

    }

    /**
     * Encode some special characters in path to CodeSource encoding for right working of CodeSource implies method. These
     * method should be extended.
     * 
     * It contain czech symbols: á, č, ď, é, ě, í, ň, ó, ř, š, ť, ú, ů, ý, ž and symbols #, %, ", =, §, <, > and space.
     * 
     * Symbols !,
     * 
     * @, $, &, *, (, ), -, +, ' and comma don't need encode.
     * 
     * @param path path to encoding
     * @return encoded path
     */
    protected String encodeSpecialCharacters(String path) {
        // this need to be first
        path = path.replaceAll("%", "%25");

        // czech symbols
        path = path.replaceAll("á", "%c3%a1");
        path = path.replaceAll("č", "%c4%8d");
        path = path.replaceAll("ď", "%c4%8f");
        path = path.replaceAll("é", "%c3%a9");
        path = path.replaceAll("ě", "%c4%9b");
        path = path.replaceAll("í", "%c3%ad");
        path = path.replaceAll("ň", "%c5%88");
        path = path.replaceAll("ó", "%c3%b3");
        path = path.replaceAll("ř", "%c5%99");
        path = path.replaceAll("š", "%c5%a1");
        path = path.replaceAll("ť", "%c5%a5");
        path = path.replaceAll("ú", "%c3%ba");
        path = path.replaceAll("ů", "%c5%af");
        path = path.replaceAll("ý", "%c3%bd");
        path = path.replaceAll("ž", "%c5%be");

        // another symbols
        path = path.replaceAll("#", "%23");
        path = path.replaceAll("\"", "%22");
        path = path.replaceAll("=", "%3d");
        path = path.replaceAll("§", "%c2%a7");
        path = path.replaceAll("<", "%3c");
        path = path.replaceAll(">", "%3e");
        path = path.replaceAll(" ", "%20");

        return path;
    }

    /**
     * Private method for getting certificates from KeyStore.
     * 
     * @param parsedCertificates signedBy part of policy file defines certificates
     * @param keystore KeyStore which is used by this policy file
     * @return array of Certificates
     * @throws Exception when there was any problem during getting Certificates
     */
    private Certificate[] getCertificates(String parsedCertificates, KeyStore keystore) throws Exception {
        String[] splitCertificates = new String[0];
        if (parsedCertificates != null) {
            splitCertificates = parsedCertificates.split(",");
        }
        if (splitCertificates.length > 0 && keystore == null) {
            throw new Exception("ER006: Keystore must be defined if signedBy is used");
        }
        List<Certificate> certList = new ArrayList<Certificate>();
        for (int i = 0; i < splitCertificates.length; i++) {
            Certificate certificate = keystore.getCertificate(splitCertificates[i]);
            if (certificate != null) {
                certList.add(certificate);
            } else {
                // return null to indicate that this permission is ignored
                return null;
            }
        }
        Certificate[] certificates;
        if (certList.isEmpty()) {
            certificates = null;
        } else {
            certificates = new Certificate[certList.size()];
            certList.toArray(certificates);
        }
        return certificates;
    }
}

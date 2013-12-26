/** Copyright 2013 Ondrej Lukas
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
  * 
  */
package net.sourceforge.prograde.policy;

import java.awt.AWTPermission;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilePermission;
import java.io.FileReader;
import java.io.Reader;
import java.io.SerializablePermission;
import java.lang.reflect.Constructor;
import java.lang.reflect.ReflectPermission;
import java.net.NetPermission;
import java.net.SocketPermission;
import java.net.URL;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.KeyStore;
import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.security.Security;
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
import net.sourceforge.prograde.debug.ProgradePolicyDebugger;
import net.sourceforge.prograde.policyparser.ParsedKeystoreEntry;
import net.sourceforge.prograde.policyparser.ParsedPermission;
import net.sourceforge.prograde.policyparser.ParsedPolicy;
import net.sourceforge.prograde.policyparser.ParsedPolicyEntry;
import net.sourceforge.prograde.policyparser.ParsedPrincipal;
import net.sourceforge.prograde.policyparser.Parser;

/**
 *
 * @author Ondrej Lukas
 */
public class ProgradePolicyFile extends Policy {
    
    private boolean priority = false; // true for grant, false for deny
    private List<ProgradePolicyEntry> allGrantEntries;
    private List<ProgradePolicyEntry> allDenyEntries;
    private List<ParsedPolicy> parsedPolicies;
    private boolean debug = false;    
    private boolean expandProperties;

    public ProgradePolicyFile() {
        refresh();
    }    
    
    @Override
    public void refresh() {
        String debugProperty = System.getProperty("java.security.debug");
        debug=false;
        if (debugProperty!=null) {            
            String[] splitDebugProperty = debugProperty.split(",");
            for (int i = 0; i < splitDebugProperty.length; i++) {
                String split = splitDebugProperty[i].trim();
                split = split.replaceAll("\"", "");
                // only these types of debug are connected with policy
                if (split.equals("all")||split.equals("policy")) {
                    debug=true;
                    break;
                }
            }
        }
        
        expandProperties = Boolean.parseBoolean(Security.getProperty("policy.expandProperties"));
        
        allGrantEntries = new ArrayList<ProgradePolicyEntry>();
        allDenyEntries = new ArrayList<ProgradePolicyEntry>();
        priority = false;
        parsedPolicies=new ArrayList<ParsedPolicy>();
        
        boolean twoEquals = false;
        String policy = System.getProperty("java.security.policy");
        if (policy!=null) {
            if (policy.startsWith("=")) {                
                twoEquals=true;
                policy=policy.substring(1);
            }
            try {
                parsedPolicies.add(new Parser(debug).parse(new File(policy)));
            } catch (Exception ex) {
                System.err.println("Given policy from property java.security.policy wasn't successfully loaded. Exception message: " + ex.getMessage());                
            }
        }
        
        // parse policies specified in java.security only in case when java.security.policy wasn't set with ==
        if (!twoEquals) {
            try {
                parsedPolicies.addAll(getJavaPolicies());
            } catch (Exception ex) {
                System.err.println("Static policy wasn't successfully loaded! Exception message: " + ex.getMessage());
            }
        }
        
        if (!twoEquals && parsedPolicies.isEmpty()) {
            try {
                initializeStaticPolicy();
            } catch (Exception ex) {
                System.err.println("Static policy wasn't successfully loaded! Exception message: " + ex.getMessage());
            }
            
        } else {
            try {
                initializePolicy();
            } catch (Exception ex) {
                System.err.println("Policy wasn't successfully initialized! Exception message: " + ex.getMessage());
            }
        }           

    } 
    
    private void initializePolicy() throws Exception {
        if (parsedPolicies.isEmpty()) {
            throw new Exception("Policy wasn't initialized!");
        }
        // set priority - priority is set according first loaded policy
        priority=parsedPolicies.get(0).getPriority();
        
        for (ParsedPolicy p : parsedPolicies) {
            KeyStore keystore=null;
            try {
                keystore = createKeystore(p.getKeystore(),p.getKeystorePasswordURL(),p.getPolicyFile());
            } catch (Exception ex) {
                System.err.println("Keystore wasn't successfully initialized! Exception message: " + ex.getMessage());
            }

            // add grant and deny policy entry
            addParsedPolicyEntries(p.getGrantEntries(),allGrantEntries,keystore,true);
            addParsedPolicyEntries(p.getDenyEntries(),allDenyEntries,keystore,false);
        }
    }
    
    private void addParsedPolicyEntries(List<ParsedPolicyEntry> parsedEntries, List<ProgradePolicyEntry> entries, KeyStore keystore,boolean grant) throws Exception {
        for (ParsedPolicyEntry p : parsedEntries) {
            entries.add(initializePolicyEntry(p,keystore,grant));
        }
    }
    
    private ProgradePolicyEntry initializePolicyEntry(ParsedPolicyEntry parsedEntry, KeyStore keystore,boolean grant) throws Exception {
        ProgradePolicyEntry entry = new ProgradePolicyEntry(grant,debug);
        
        // codesource     
        if (parsedEntry.getCodebase()!=null || parsedEntry.getSignedBy()!=null) {
            CodeSource cs = createCodeSource(parsedEntry,keystore);
            if (cs!=null) {
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
                String principal = gainPrincipalFromAlias(expandStringWithProperty(p.getAlias()),keystore);
                if (principal!=null) {
                    entry.addPrincipal(new ProgradePrincipal("javax.security.auth.x500.X500Principal",principal,false,false));
                } else {
                    // it happens if there is alias which isn't contain in keystore
                    entry.setNeverImplies(true);
                    // any next isn't needed because entry will never implies anything
                    return entry;
                }                
            } else {
                entry.addPrincipal(new ProgradePrincipal(p.getPrincipalClass(),expandStringWithProperty(p.getPrincipalName()),
                        p.hasClassWildcard(),p.hasNameWildcard()));
            }
        }        
        
        //permissions
        for (ParsedPermission p : parsedEntry.getPermissions()) {
            Permission perm = createPermission(p, keystore);
            if (perm!=null) {
                entry.addPermission(perm);
            }                    
        }
        
        return entry;
    }
    
    @Override
    public boolean implies(ProtectionDomain protectionDomain, Permission permission) {
        
        // this should never happen
        if (protectionDomain==null) {
            return false;
        }
        
        // everything is granted in this case
        if (protectionDomain.getCodeSource()==null){
            return true;
        }
        
        if (priority) { // branch for grant priority
            if (debug) {
                ProgradePolicyDebugger.log("Searching for granting for permission: " + permission + " ...");
            }
            if(grant(protectionDomain,permission)) {
                if (debug) {
                    ProgradePolicyDebugger.log("Granting permission found, grant access.");
                }
                return true;
            } else {
                if (debug) {
                    ProgradePolicyDebugger.log("Granting permission wasn't found, searching for denying...");
                }
                boolean toReturn = !deny(protectionDomain,permission);
                if (debug) {
                    if(toReturn) {
                        ProgradePolicyDebugger.log("Denying permission wasn't found, grant access.");
                    } else {
                        ProgradePolicyDebugger.log("Denying permission found, deny access.");
                    }                    
                }
                return toReturn;
            }            
        } else { // branch for deny priority
            if (debug) {
                ProgradePolicyDebugger.log("Searching for denying for permission: " + permission + " ...");
            }
            if(deny(protectionDomain,permission)) {
                if (debug) {
                    ProgradePolicyDebugger.log("Denying permission found, deny access.");
                }
                return false;
            } else {
                if (debug) {
                    ProgradePolicyDebugger.log("Denying permission wasn't found, searching for granting...");
                }
                boolean toReturn = grant(protectionDomain,permission);
                if (debug) {
                    if(toReturn) {
                        ProgradePolicyDebugger.log("Granting permission found, grant access.");
                    } else {
                        ProgradePolicyDebugger.log("Granting permission wasn't found, deny access.");
                    }                    
                }
                return toReturn;
            }            
        }
    }

    // return true = grant it
    private boolean grant(ProtectionDomain domain, Permission permission) {
        return grantOrDenyPermission(domain,permission,allGrantEntries);
    }

    // return true = deny it
    private boolean deny(ProtectionDomain domain, Permission permission) {
        return grantOrDenyPermission(domain,permission,allDenyEntries);
    }
    
    private boolean grantOrDenyPermission(ProtectionDomain domain, Permission permission, List<ProgradePolicyEntry> policyEntriesList) {
        for (ProgradePolicyEntry entry : policyEntriesList) {
            if (entry.implies(domain, permission)) {
                return true;
            }
        }
        return false;
    }

    private Permission createPermission(ParsedPermission p, KeyStore keystore) throws Exception {
        if (p==null) {
            return null;
        }
        
        String permissionName = expandStringWithProperty(p.getPermissionName());
        String actions = expandStringWithProperty(p.getActions());

        Class<?> clazz;
        try {
            clazz = Class.forName(p.getPermissionType());
        } catch (ClassNotFoundException ex) {            
            Certificate[] certificates = getCertificates(expandStringWithProperty(p.getSignedBy()), keystore);
            if (p.getSignedBy()!=null && certificates==null) {
                if (debug) {
                    ProgradePolicyDebugger.log("Permission with signedBy " + p.getSignedBy() + " is ignored. Certificate wasn't successfully found or loaded from keystore");
                }
                return null;
            }
            return new UnresolvedPermission(p.getPermissionType(),permissionName,actions,certificates);
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
            System.err.println("IllegalArgumentException in permission: [" + 
                    p.getPermissionType() + ", " + permissionName + ", " + actions + "]");
            return null;
        }
        
        // check signedBy permission for classes which weren't loaded by boostrap classloader
        // in some java clazz.getClassLoader() returns null for boostrap classloader 
        if (clazz.getClassLoader()!=null) {
            // another check whether clazz.getClassLoader() isn't bootstrap classloader
            if (!clazz.getClassLoader().equals(clazz.getClassLoader().getParent())) {
                if (p.getSignedBy()!=null) {
                    Certificate[] signers = (Certificate[]) clazz.getSigners();
                    if (signers==null) {
                        return null;
                    } else {
                        Certificate[] certificates = getCertificates(expandStringWithProperty(p.getSignedBy()), keystore);
                        if (certificates==null) {
                            return null;
                        } else {
                            for (int i = 0; i < certificates.length; i++) {
                                Certificate certificate = certificates[i];
                                boolean contain = false;
                                for (int j = 0; j < signers.length; j++) {
                                    Certificate signedCertificate = signers[j];
                                    if(certificate.equals(signedCertificate)) {
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
            Constructor<?> c = clazz.getConstructor(String.class,String.class);
            return (Permission) c.newInstance(new Object[] {permissionName,actions});
        } catch (NoSuchMethodException ex1) {
            try {
                Constructor<?> c = clazz.getConstructor(String.class);
                return (Permission) c.newInstance(new Object[] {permissionName});
            } catch (NoSuchMethodException ex2) {
                Constructor<?> c = clazz.getConstructor();
                return (Permission) c.newInstance(new Object[] {});
            }
        }
    }
    
    private String expandStringWithProperty(String s) throws Exception {
        // if expandProperties is false, don't expand property
        if (!expandProperties) {
            return s;
        }
        // if string doesn't contain property, returns original string
        if (s == null || s.indexOf("${") == -1) {
            return s;
        }
        String toReturn="";
        String[] split = s.split(Pattern.quote("${"));
        toReturn+=split[0];
        for (int i = 1; i < split.length; i++) {
            String part = split[i];
            // don't expand ${{...}}
            if (part.startsWith("{")) {
                toReturn+=("${"+part);
                continue;
            }
            String[] splitPart = part.split("}",2);
            if (splitPart.length<2) {
                throw new Exception("ER001: Expand property without end } or inner property expansion!");
            } else {
                // add expanded property
                // ${/} = file.separator
                if (splitPart[0].equals("/")) {
                    toReturn+=File.separator;
                } else {
                    toReturn+=System.getProperty(splitPart[0]);
                }                
                toReturn+=splitPart[1];
            }            
        }        
        return toReturn;
    }
    
    private CodeSource createCodeSource(ParsedPolicyEntry parsedEntry, KeyStore keystore) throws Exception {
        String parsedCodebase = expandStringWithProperty(parsedEntry.getCodebase());
        String parsedCertificates = expandStringWithProperty(parsedEntry.getSignedBy());
        String[] splitCertificates = new String[0];
        if (parsedCertificates!=null) {
            splitCertificates = parsedCertificates.split(",");
        }
        if (splitCertificates.length>0 && keystore==null) {
            throw new Exception("ER002: Keystore must be defined if signedBy is used");
        }        
        
        List<Certificate> certList = new ArrayList<Certificate>();   
        
        for (int i = 0; i < splitCertificates.length; i++) {   
            Certificate certificate = keystore.getCertificate(splitCertificates[i]);
            if (certificate!=null) {
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
        if (parsedCodebase==null) {
            url = null;
        } else {
            url = new URL(parsedCodebase);
        }      
        CodeSource cs = new CodeSource(adaptURL(url),certificates);
        return cs;
    }
    
    private URL adaptURL(URL url) throws Exception {    
        if (url != null && url.getProtocol().equals("file")) {
            String host = url.getHost();
            // if it is local file
            if (host == null || host.equals("") || host.equals("~") || host.equalsIgnoreCase("localhost")) {
                // make path readable for specific OS
                String path = url.getFile().replace('/', File.separatorChar);
                
                File f;
                if (path.endsWith("*")) {
                    path = path.substring(0, path.length()-1) + "-";
                    f = new File(path);
                    path = f.getCanonicalPath();
                    path = path.substring(0, path.length()-1) + "*";
                } else {
                    f = new File(path);
                    path = f.getCanonicalPath();
                }
                if (!path.startsWith("/")) {
                    path = "/" + path;
                }
                if (!path.endsWith("/") && f.isDirectory()) {
                    path = path + "/";                    
                }
                                
                path = encodeSpecialCharacters(path);
                
                path = path.replace(File.separatorChar, '/');
               
                return new URL("file", "", path);
            }
        }        
        return url;
    }    

    private KeyStore createKeystore(ParsedKeystoreEntry parsedKeystoreEntry, String keystorePasswordURL, File policyFile) throws Exception {
        if (parsedKeystoreEntry==null) {
            return null;
        }
        KeyStore toReturn;
        String keystoreURL = expandStringWithProperty(parsedKeystoreEntry.getKeystoreURL());
        String keystoreType = expandStringWithProperty(parsedKeystoreEntry.getKeystoreType());
        String keystoreProvider = expandStringWithProperty(parsedKeystoreEntry.getKeystoreProvider());

        if (keystoreURL==null) {
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
        if (keystorePasswordURL!=null) {
            keystorePassword = readKeystorePassword(expandStringWithProperty(keystorePasswordURL),policyFile);
        }
                
        // try relative path to policy file
        String path = getPolicyFileHome(policyFile);
        File f = null;
        if (path!=null) {
            f = new File(path, keystoreURL);
        }        
        if (f==null || !f.exists()) {
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
        while((len=reader.read(buffer))>0 ) {
            sb.append(buffer, 0, len ); 
        }
        reader.close();
        return sb.toString().trim().toCharArray();
    }

    private String gainPrincipalFromAlias(String alias, KeyStore keystore) throws Exception {
        if (keystore==null) {
            return null;
        }
        if (!keystore.containsAlias(alias)) {
            return null;
        }
        
        Certificate certificate = keystore.getCertificate(alias);
        if (certificate == null || !(certificate instanceof X509Certificate)) {
            return null;
        }
        
        X509Certificate x509Certificate = (X509Certificate)certificate;
        X500Principal principal = new X500Principal(x509Certificate.getSubjectX500Principal().toString());
        return principal.getName();
    }
    
    private String getPolicyFileHome(File file) throws Exception {
        if (file==null || !file.exists()) {
            return null;
        }
        return file.getAbsoluteFile().getParent();        
    }    
    
    private List<ParsedPolicy> getJavaPolicies() {
        List<ParsedPolicy> list = new ArrayList<ParsedPolicy>();    
        
        int counter=1;
        String policyUrl=null;
        while((policyUrl = Security.getProperty("policy.url."+counter)) != null) {
            if (policyUrl.startsWith("file:")) {
                try {
                    policyUrl=expandStringWithProperty(policyUrl.substring(5));
                } catch (Exception ex) {
                    System.err.println("Expanding filepath in policy policy.url." + counter + "=file:" + policyUrl + " failed. Exception message: " + ex.getMessage());
                    counter++;
                    continue;
                }
                ParsedPolicy p = null;
                try {
                    p = new Parser(debug).parse(new File(policyUrl));
                    if (p!=null) {
                        list.add(p);
                    } else {
                        System.err.println("Parsed policy policy.url." + counter + "=file:" + policyUrl + " is null");
                    }
                } catch (Exception ex) {
                    System.err.println("Policy policy.url." + counter + "=file:" + policyUrl + " wasn't successfully parsed. Exception message: " + ex.getMessage());
                }                
            } else {
                System.err.println("Sorry, this policy works only with local text policy file! "
                        + "This policy couldn't be loaded: policy.url."+counter + "=" + policyUrl);
            }
            counter++;
        }       
        
        return list;
    }

    private void initializeStaticPolicy() throws Exception {
        
        //grant codeBase "file:${{java.ext.dirs}}/*" {
        //    permission java.security.AllPermission;
        //};        
        ProgradePolicyEntry p1 = new ProgradePolicyEntry(true,debug);
        Certificate[] certificates = null;                
        URL url = new URL(expandStringWithProperty("file:${{java.ext.dirs}}/*"));            
        CodeSource cs = new CodeSource(adaptURL(url),certificates);
        p1.setCodeSource(cs);
        p1.addPermission(new AllPermission());
        allGrantEntries.add(p1);        
        
        //grant { 	
        //    permission java.lang.RuntimePermission "stopThread";
        //    permission java.net.SocketPermission "localhost:1024-", "listen";
        //    permission java.util.PropertyPermission "java.version", "read";
        //    permission java.util.PropertyPermission "java.vendor", "read";
        //    permission java.util.PropertyPermission "java.vendor.url", "read";
        //    permission java.util.PropertyPermission "java.class.version", "read";
        //    permission java.util.PropertyPermission "os.name", "read";
        //    permission java.util.PropertyPermission "os.version", "read";
        //    permission java.util.PropertyPermission "os.arch", "read";
        //    permission java.util.PropertyPermission "file.separator", "read";
        //    permission java.util.PropertyPermission "path.separator", "read";
        //    permission java.util.PropertyPermission "line.separator", "read";
        //    permission java.util.PropertyPermission "java.specification.version", "read";
        //    permission java.util.PropertyPermission "java.specification.vendor", "read";
        //    permission java.util.PropertyPermission "java.specification.name", "read";
        //    permission java.util.PropertyPermission "java.vm.specification.version", "read";
        //    permission java.util.PropertyPermission "java.vm.specification.vendor", "read";
        //    permission java.util.PropertyPermission "java.vm.specification.name", "read";
        //    permission java.util.PropertyPermission "java.vm.version", "read";
        //    permission java.util.PropertyPermission "java.vm.vendor", "read";
        //    permission java.util.PropertyPermission "java.vm.name", "read";
        //};
        ProgradePolicyEntry p2 = new ProgradePolicyEntry(true,debug);
        p2.addPermission(new RuntimePermission("stopThread"));
        p2.addPermission(new SocketPermission("localhost:1024-","listen"));
        p2.addPermission(new PropertyPermission("java.version","read"));
        p2.addPermission(new PropertyPermission("java.vendor","read"));
        p2.addPermission(new PropertyPermission("java.vendor.url","read"));
        p2.addPermission(new PropertyPermission("java.class.version","read"));
        p2.addPermission(new PropertyPermission("os.name","read"));
        p2.addPermission(new PropertyPermission("os.version","read"));
        p2.addPermission(new PropertyPermission("os.arch","read"));
        p2.addPermission(new PropertyPermission("file.separator","read"));
        p2.addPermission(new PropertyPermission("path.separator","read"));
        p2.addPermission(new PropertyPermission("line.separator","read"));
        p2.addPermission(new PropertyPermission("java.specification.version","read"));
        p2.addPermission(new PropertyPermission("java.specification.vendor","read"));
        p2.addPermission(new PropertyPermission("java.specification.name","read"));
        p2.addPermission(new PropertyPermission("java.vm.specification.version","read"));
        p2.addPermission(new PropertyPermission("java.vm.specification.vendor","read"));
        p2.addPermission(new PropertyPermission("java.vm.specification.name","read"));
        p2.addPermission(new PropertyPermission("java.vm.version","read"));
        p2.addPermission(new PropertyPermission("java.vm.vendor","read"));
        p2.addPermission(new PropertyPermission("java.vm.name","read"));
        allGrantEntries.add(p2);

    }

    /*
     * Encode some special characters in path to CodeSource encoding for right working of CodeSource implies method.
     * These method should be extended.
     * It contain czech symbols: á, č, ď, é, ě, í, ň, ó, ř, š, ť, ú, ů, ý, ž
     * and symbols #, %, ", =, §, <, > and space.
     * Symbols !, @, $, &, *, (, ), -, +, ' and comma don't need encode.
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

    private Certificate[] getCertificates(String parsedCertificates, KeyStore keystore) throws Exception {
        String[] splitCertificates = new String[0];
            if (parsedCertificates!=null) {
                splitCertificates = parsedCertificates.split(",");
            }
            if (splitCertificates.length>0 && keystore==null) {
                throw new Exception("ER006: Keystore must be defined if signedBy is used");
            }        
            List<Certificate> certList = new ArrayList<Certificate>();   
            for (int i = 0; i < splitCertificates.length; i++) {   
                Certificate certificate = keystore.getCertificate(splitCertificates[i]);
                if (certificate!=null) {
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

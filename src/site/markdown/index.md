![pro-grade](images/prograde.png)

The **pro-grade** library provides implementation of custom Java Security Managers and Security Policies.
The main component is a *Java Security Policy implementation with denying rules* as an addition to standard
*grant* rules.

Download the [latest binaries](http://sourceforge.net/projects/pro-grade/files/latest/download)
from the [SourceForge project pages](http://sourceforge.net/projects/pro-grade/).

## Security Managers

**pro-grade** library uses custom Java Security Managers to install Security Policy objects by a standard Java way.

Just use right value for  **`java.security.manager`** system property and add it to java arguments. E.g.

```Shell
java -Djava.security.manager=net.sourceforge.prograde.sm.DumpMissingPermissionsJSM ...
```

The library contains following security manager implementations:
 
 * ProGrade policy
 * policy generator
 * permissions debugger

---

### ProGrade Policy

*Let's deny it!*

**`net.sourceforge.prograde.sm.ProGradeJSM`**

Extension to standard Java Security Manager which adds possibility of using **deny** rules.

Utilize the possibility of better control what's granted to whom.

[Read more ...](pro-grade.html)

#### ProGrade Policy example

```Java
priority "deny";

// grant full access to /tmp folder
grant {
	permission java.io.FilePermission "/tmp/-", "read,write";
};

// deny write access for a single subfolder in /tmp
deny {
	permission java.io.FilePermission "/tmp/static/-", "write";
};
```

### Policy Generator

*Create policy files without pain!*

**`net.sourceforge.prograde.sm.PolicyFileGeneratorJSM`**

Policy file generator which creates Java policy files. The generated policies can be used together with
the standard SecurityManager or pro-grade.

[Read more ...](policy-file-generator.html)

### Policy Debugger

*Show me, what's missing in my policy!*

**`net.sourceforge.prograde.sm.DumpMissingPermissionsJSM`**

Simple and comfortable way to find, what permissions are missing in your policy files.
Stop fighting with denied permissions one by one using obsolete `-Djava.security.debug` property.
And print only the information which really counts. 

This Security Manager prints permissions missing in your policy to error stream.

[Read more ...](missing-permissions-dumper.html)

--- 

## Usage

You can either specify the Security Manager implementation as `java` command line argument
or use the Java API.

### Command line arguments

```Shell
java -classpath [ORIGINAL_CP:]/path/to/prograde.jar \
     -Djava.security.manager=net.sourceforge.prograde.sm.ProGradeJSM \
     -Djava.security.policy=/path/to/prograde.policy \
     ...
```

#### Executable JARs

The `-classpath` (`-cp`) java argument is not used when an application is started 
using `-jar` Java argument. In such case either add `pro-grade.jar` to the classpath referenced 
from the `META-INF/MANIFEST.MF` in the jar or use the classic for starting Java apps:

```
java -classpath <YourClassPath> [otherJvmArgs] <MainClassOfTheApplication> [ApplicationParams]
```  

### Java API

Simply set the security manager which will install correct policy for you.

```Java
System.setSecurityManager(new ProGradeJSM());
```

You can also use another way. If you already have a security manager installed
and you only want to use some of pro-grade policy implementations:

```Java
System.setProperty("java.security.policy","/path/to/prograde.policy");
java.security.Policy.setPolicy(new net.sourceforge.prograde.policy.ProGradePolicy());
```

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

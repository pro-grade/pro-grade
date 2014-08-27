# ![pro-grade](images/prograde.png) pro-grade

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

### ProGrade Policy - Let's deny it!

Class name: **`net.sourceforge.prograde.sm.ProGradeJSM`**

Standard SecurityManager with possibility of using **deny** rules. 

[Read more ...](pro-grade.html)

#### ProGrade Policy file example

```Java
// following entry can be ommited because "deny" value is the default
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

### Generator - Create policy files

Class name: **`net.sourceforge.prograde.sm.PolicyFileGeneratorJSM`**

Policy file generator which creates policy files. The generated policies can be used together with
the standard SecurityManager or pro-grade.

[Read more ...](policy-file-generator.html)

### Debugger - Print missing permissions

Class name: **`net.sourceforge.prograde.sm.DumpMissingPermissionsJSM`**

Prints missing permissions to error stream. 

[Read more ...](missing-permissions-dumper.html)

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

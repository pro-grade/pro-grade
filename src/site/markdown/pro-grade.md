# ProGrade Policy

**ProGrade = Policy Rules Of GRanting And DEnying**

Standard Java Policy implementation is not able to cover some important use-cases in Permissions handling. 
The ProGrade Policy helps to fix this by adding **`deny`** entries to policy files. 

Basic scenario for using the ProGrade policy is when you want to grant permissions with some exceptions. 
For instance:

 * permit all permissions, but deny network access for the application
 * allow full access (read/write) to a directory, but read-only access to its subdirectory

## Quickstart 

### 1. Create ProGrade policy file

Create plain-text policy file (e.g. `"${HOME}/myapp-prograde.policy"`) with your favorite editor:

```
// Grant all to everyone
grant {
    permission java.security.AllPermission;
};
// Deny access to a network via sockets
deny {
    permission java.net.SocketPermission "*", "accept,connect,listen,resolve";
}
```

### 2. Use ProGrade Security Manager 

Specify policy file and security manager implementation as `java` command line arguments argument:

```
java \
     "-Djava.security.manager=net.sourceforge.prograde.sm.ProGradeJSM" \
     "-Djava.security.policy=${HOME}/myapp-prograde.policy" \
     -classpath "[ORIGINAL_CP:]/path/to/prograde.jar" \
     [otherJvmArgs] <application.main.class.name> [applicationParameters] 
```

## Policy files

The standard Policy implementation and syntax of policy files is described in 
[Oracle Java documentation](http://docs.oracle.com/javase/7/docs/technotes/guides/security/PolicyFiles.html).

The **ProGrade** policy adds **`deny`** entries with the same syntax as **`grant`** entries have. 

### Priorities for Grant and Deny

Priorities of `grant` and `deny` entries can be controlled in policy files. There is a special entry called **`priority`**,
which takes as an argument name entry with bigger priority.

For instance, the "**Deny overrides mode**" can have following entry in the policy file.

```
priority "deny";
```

The default priority is backward compatible with standard policy file implementation in Java - i.e. `"deny"`.

#### Deny overrides mode

The default mode. Decision for permission check is based on following rule:

***The checked permission is granted if and only if the policy file contains an `grant` entry which implies the permission
and it doesn't contain any `deny` entry which implies the permission.***

#### Grant overrides mode

Decision for permission check is based on following rule:

***The checked permission is granted if and only the policy file contains an `grant` entry which implies the permission
or it doesn't contain any `deny` entry which implies the permission.***

### Decision making table

The checked permission is implied ...| priority "deny"; (default) | priority "grant";
-------------------------------------|----------------------------|-----------------
neither from any `grant` nor from `deny` entry in policy file | denied | granted
from a `grant` entry but not from a `deny` entry in policy file | granted | granted
from a `deny` entry but not from a `grant` entry in policy file | denied | denied
from both `grant` and `deny` entries in policy file | denied | granted

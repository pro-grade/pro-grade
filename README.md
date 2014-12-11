# pro-grade library

The pro-grade library provides implementation of custom Java Security Managers and Security Policies. The main component is a Java Security Policy implementation with denying rules as an addition to standard grant rules.

*ProGrade = "Policy Rules Of GRanting And DEnying".*

## Build project
Simply use:

```Shell
$ mvn clean install
```

## Run your App with ProGrade Security manager

Only thing which you need to do is to add standard java properties for enabling security manager:

```Shell
java \
     "-Djava.security.manager=net.sourceforge.prograde.sm.ProGradeJSM" \
     "-Djava.security.policy=/path/to/your-app-prograde.policy" \
     ...
```

## Java Policy File Generator

The generator is a custom Java Security Manager, which generates a simple policy file from permissions checked by Java Application. The generated policy file can be used with the standard Java Security Manager afterwards.

### Generate the policy file

Simply use the custom Java Security Manager class *net.sourceforge.prograde.generator.PolicyFileGeneratorJSM* when starting your Java application. Then go through usual application worklows and the generator will create a policy file with *missing permissions* for you.

Other steps are optional:

* configure the initial policy file (if you already have one)
  * set the path to the java.security.policy system property
  * use 2 equal characters “==” if you don’t want to use default policy configured for JRE 
* configure the output file
  * set the path to the prograde.generated.policy system property
  * if you don’t set this property, then a new file will be generated in the user’s temporary directory

```Shell
java \
    -Djava.security.manager=net.sourceforge.prograde.sm.PolicyFileGeneratorJSM \
    -Djava.security.policy==/path/to/initial.policy \
    -Dprograde.generated.policy=/tmp/generated.policy \
    ...
```

### Use the generated policy

Test the generated.policy file with standard Java Security Manager: 

```Shell
java \
    -Djava.security.manager \
    -Djava.security.policy==/tmp/generated.policy \
    ..
```

### ProGrade as the underlying policy

The standard Java Policy implementation is used as the underlying implementation for the policy file generator. You can use ProGrade policy instead when you set *prograde.use.own.policy* system property to true.

```Shell
-Dprograde.use.own.policy=true
```


## Work with denying rules

### Deny entries

It is a quite similar as standard policy in Java. It also works with policy file with grant entries, but you can also write deny entries - it uses same definitions as grant entries but meaning of them is opposite. For denying rules use keyword "deny".

You can take a look into [policy files in pro-grade testsuite](https://github.com/pro-grade/progradeTests/tree/master/src/test/resources/policyfiles).

### Priority entry

You can set *`priority`* on `"grant"` or `"deny"`. The `priority` says what rules is stronger when grant and deny are in conflict. If you use deny priority, all actions are as default denied. If you use grant priority, all actions are as default granted. It means that standard Java uses as 
default `"deny"` priority.

### Sample policy

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

## License

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

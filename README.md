# pro-grade library

The pro-grade library provides implementation of custom Java Security Managers and Security Policies. The main component is a Java Security Policy implementation with denying rules as an addition to standard grant rules.

*ProGrade = "Policy Rules Of GRanting And DEnying".*

## Build project
Simply use:

	$ mvn clean install

## Run your App with ProGrade Security manager

Only thing which you need to do is to add standard java properties for enabling security manager:

```Shell
java \
     "-Djava.security.manager=net.sourceforge.prograde.sm.ProGradeJSM" \
     "-Djava.security.policy=/path/to/your-app-prograde.policy" \
     ...
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

# Prograde

Prograde means "Policy Rules Of GRanting And DEnying" and it is maven project for using Java Security Policy with denying rules.

## Build project
Simply use:

	$ mvn clean install

## Add Prograde to your application

Only thing what you need to do is running your application with net.sourceforge.prograde.sm.ProgradeSecurityManager. ProgradeSecurityManager sets ProgradePolicyFile as Policy of the application.

## Work with denying rules

### Deny entries

It is a quite similar as standard policy in Java. It also works with policy file with grant entries, but you can also write deny entries - it uses same definitions as grant entries but meaning of them is opposite. For denying rules use keyword "deny".

You can take a look at [prograde testsuite](https://github.com/pro-grade/progradeTests). It contains some configuration of policy files (for tests) and you'll look how exactly using denying rules.

### Priority entry

You can set priority on "grant" or "deny". Priority say what rules is stronger when grant and deny are in conflict. If you use deny priority, all actions are as default denied. If you use grant priority, all actions are as default granted. It means that standard Java uses as default "deny" priority.

Priority entry has only one occur in policy file and it is loaded only from first loaded policy file and use for all security policies.

For setting priority use keyword "priority" and one of options "grant" or "deny".

## License

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

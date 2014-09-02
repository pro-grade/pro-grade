# Java Missing Permissions Dumper

If you don't need to [generate Java Policy file](java-policy-file-generator.html) and you only want to check
in console which Java Permissions are missing in your policy file, then use the second custom 
Java Security Manager, which prints the missing permissions to **`System.err`** stream.

## Dump the missing permissions

Main step is to use a custom Java Security Manager class **`net.sourceforge.prograde.generator.DumpMissingPermissionsJSM`**
when starting your Java application. Then go through usual application worklows and the generator will print
the missing permissions to the **error stream**.

Other steps are optional:

* configure the *initial policy file* (if you already have one)
    * set the path to the `java.security.policy` system property
    * use 2 equal characters "==" if you don't want to use default policy configured for JRE

```Shell
java \
    -Djava.security.manager=net.sourceforge.prograde.sm.DumpMissingPermissionsJSM \
    -Djava.security.policy==/path/to/initial.policy \
    ...
```

## Use ProGrade as the underlying policy

The standard Java Policy implementation is used as the underlying implementation for the missing permissions dumper.
You can use ProGrade policy instead when you set **`prograde.use.own.policy`** system property to true.

    -Dprograde.use.own.policy=true

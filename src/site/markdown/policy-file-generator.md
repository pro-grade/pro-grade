# Java Policy File Generator

The generator is a custom Java Security Manager, which generates a simple policy file from permissions 
checked by Java Application. The generated policy file can be used with 
the standard Java Security Manager afterwards.

## Generate the policy file

Simply use the custom Java Security Manager class **`net.sourceforge.prograde.generator.PolicyFileGeneratorJSM`**
when starting your Java application. Then go through usual application worklows and the generator will create a
policy file with **missing permissions** for you.

Other steps are optional:

* configure the *initial policy file* (if you already have one)
    * set the path to the `java.security.policy` system property
    * use 2 equal characters "==" if you don't want to use default policy configured for JRE
* configure the *output file*
    * set the path to the `prograde.generated.policy` system property
    * if you don't set this property, then a new file will be generated in the user's temporary directory

```Shell
java \
    -Djava.security.manager=net.sourceforge.prograde.generator.PolicyFileGeneratorJSM \
    -Djava.security.policy==/path/to/initial.policy \
    -Dprograde.generated.policy=/tmp/generated.policy \
    ...
```

The permissions granted in `initial.policy` will not be included in the `generated.policy`.
If you want to have all permissions included in the generated file, 
then use an empty file as the `initial.policy`.

## Use the generated policy

Test the `generated.policy` file with standard Java Security Manager: 

```Shell
java \
    -Djava.security.manager \
    -Djava.security.policy==/tmp/generated.policy \
    ...
``` 
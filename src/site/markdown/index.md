# ![pro-grade](images/prograde.png) pro-grade

**Policy Rules Of GRanting And DEnying**

*Java Security Policy implementation with denying rules*

## Get it now

Download the [latest binaries](http://sourceforge.net/projects/pro-grade/files/latest/download)
from the [SourceForge project pages](http://sourceforge.net/projects/pro-grade/).

## Maven dependency

```xml
<dependency>
    <groupId>net.sourceforge.pro-grade</groupId>
    <artifactId>pro-grade</artifactId>
    <version>1.1</version>
</dependency>
```

## Policy file sample

```
priority "deny";

grant {
	permission java.io.FilePermission "/tmp/*", "read,write";
};

deny {
	permission java.io.FilePermission "/tmp/static/*", "write";
};
```

## Usage

```Shell
java -classpath [ORIGINAL_CP]:/path/to/prograde.jar \
     -Djava.security.manager=... \
     -Djava.security.policy=/path/to/prograde.policy \
     com.acme.Main
```

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

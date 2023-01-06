# Usage

## Maven

``` xml
<dependency>
  <groupId>dev.dotfox</groupId>
  <artifactId>capbac-bls</artifactId>
  <version>1.0-SNAPSHOT</version>
</dependency>

<repository>
  <id>DotFox</id>
  <url>https://maven.pkg.github.com/DotFox/capbac-bls</url>
  <snapshots>
    <enabled>true</enabled>
  </snapshots>
</repository>

<repository>
  <id>consensys</id>
  <url>https://artifacts.consensys.net/public/maven/maven/</url>
</repository>
```

## Clojure

``` edn
{:deps {dev.dotfox/capbac-bls {:mvn/version "1.0-SNAPSHOT"}}
 :mvn/repos {"DotFox" {:url "https://maven.pkg.github.com/DotFox/capbac-bls"}
             "consensys" {:url "https://artifacts.consensys.net/public/maven/maven/"}}}
```

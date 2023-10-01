[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![build](https://github.com/p-ssanders/jvex/actions/workflows/build.yml/badge.svg)](https://github.com/p-ssanders/jvex/actions/workflows/build.yml)
[![maven-central](https://img.shields.io/maven-central/v/dev.samsanders.openvex/jvex)](https://central.sonatype.com/artifact/dev.samsanders.openvex/jvex/overview)
[![javadoc](https://javadoc.io/badge2/dev.samsanders.openvex/jvex/javadoc.svg)](https://javadoc.io/doc/dev.samsanders.openvex/jvex)


#   jvex

Java library for generating, consuming, and operating on VEX documents based on the [OpenVEX Specification v0.2.0](https://openvex.dev/)

##  Installing

Maven
```xml
<dependency>
  <groupId>dev.samsanders.openvex</groupId>
  <artifactId>jvex</artifactId>
  <version>1.0.0</version>
</dependency>
```

Gradle
```groovy
implementation 'dev.samsanders.openvex:jvex:1.0.0'
```

##  Usage

<details>
<summary>Create a VEX Document</summary>

This example creates a `Document` using the public constructor.

```java
Document document = new Document("Spring Builds <spring-builds@users.noreply.github.com>");
document.setRole("Project Release Bot");

Product product = new Product(URI.create("pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb"));
product.setIdentifiers(new Identifiers(new PackageURL("pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb")));

Hashes hashes = new Hashes();
hashes.setSha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
product.setHashes(hashes);

Vulnerability vulnerability = new Vulnerability("CVE-2021-44228");
vulnerability.setId(URI.create("https://nvd.nist.gov/vuln/detail/CVE-2021-44228"));
vulnerability.setDescription("Remote code injection in Log4j");
vulnerability.setAliases(Collections.singletonList("GHSA-jfh8-c2jp-5v3q"));

Statement statement = new Statement(Collections.singletonList(product), vulnerability, Status.not_affected);
statement.setJustification(Justification.vulnerable_code_not_in_execute_path);
statement.setImpactStatement("Spring Boot users are only affected by this vulnerability if they have switched the " +
        "default logging system to Log4J2. The log4j-to-slf4j and log4j-api jars that we include in spring-boot-starter-logging " +
        "cannot be exploited on their own. Only applications using log4j-core and including user input in log messages are vulnerable.");
document.getStatements().add(statement);
```

The document can be serialized to JSON using the `toJson` convenience method that delegates to a pre-configured
jackson-databind `ObjectMapper`, or you can use your own `ObjectMapper`.
Additionally, any framework that uses jackson-databind, (e.g.: Spring Web MVC) can be used to serialize a `Document`.

The `Document` above will serialize to the following JSON:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-7b79113df873170fddc9def6166d7e7c8ba4d8ad09fb164005c41cf82d8b6068",
  "author": "Spring Builds <spring-builds@users.noreply.github.com>",
  "role": "Project Release Bot",
  "timestamp": "2023-09-28T10:45:44.884207-06:00",
  "version": 1,
  "tooling": "jvex/1.0.0",
  "statements": [
    {
      "products": [
        {
          "@id": "pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb",
          "identifiers": {
            "purl": "pkg:oci/git@sha256%3A23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb"
          },
          "hashes": {
            "sha-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
          }
        }
      ],
      "vulnerability": {
        "name": "CVE-2021-44228",
        "description": "Remote code injection in Log4j",
        "aliases": [
          "GHSA-jfh8-c2jp-5v3q"
        ],
        "@id": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
      },
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "Spring Boot users are only affected by this vulnerability if they have switched the default logging system to Log4J2. The log4j-to-slf4j and log4j-api jars that we include in spring-boot-starter-logging cannot be exploited on their own. Only applications using log4j-core and including user input in log messages are vulnerable."
    }
  ]
}
```

Note the defaults:

- `@context` defaults to `https://openvex.dev/ns/v0.2.0`
- `@id` is generated based on the "canonical hash" algorithm
- `timestamp` defaults to now
- `version` defaults to 1
- `tooling` defaults to "jvex/1.0.0"

</details>

<details>
<summary>Consume a VEX Document</summary>

Deserialize JSON using `jackson-databind` or a framework that uses it (e.g.: Spring Web MVC)
The deserialization approach accepts any valid OpenVEX 0.2.0 JSON.
It fails if the JSON is invalid according to the spec (i.e.: MUSTs, required fields, types, conditional logic, etc.)

```java
Document from(InputStream inputStream) throws IOException {
    ObjectReader reader = new ObjectMapper().registerModule(new JavaTimeModule()).reader();
    return reader.readValue(inputStream, Document.class);
}
```

```java
@PostMapping
public ResponseEntity<Void> create(@RequestBody Document document) {
    // ...
}
```

</details>

<details>

<summary>Add a Statement to a Document</summary>

TODO

</details>
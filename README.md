[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![build](https://github.com/p-ssanders/jvex/actions/workflows/build.yml/badge.svg)](https://github.com/p-ssanders/jvex/actions/workflows/build.yml)
[![maven-central](https://img.shields.io/maven-central/v/dev.samsanders.openvex/jvex)](https://central.sonatype.com/artifact/dev.samsanders.openvex/jvex/overview)



#   jvex

Java types for OpenVEX documents based on the [OpenVEX Specification v0.2.0](https://openvex.dev/)

##  Installing

Maven
```xml
<dependency>
  <groupId>dev.samsanders.openvex</groupId>
  <artifactId>jvex</artifactId>
  <version>0.0.1</version>
</dependency>
```

Gradle
```groovy
implementation 'dev.samsanders.openvex:jvex:0.0.1'
```

##  Example Usage: Generate a VEX Document

```java
public class Application {

    public static void main(String[] args) {
        Document document = new Document("https://openvex.dev/ns/v0.2.0",
                URI.create("https://openvex.dev/docs/public/vex-a06f9de1ad1b1e555a33b2d0c1e7e6ecc4dc1800ff457c61ea09d8e97670d2a3"),
                "Wolfi J. Inkinson");
        document.setRole("Senior VEXing Engineer");
        Product product = new Product(URI.create("pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb"));
        Statement statement = new Statement(Collections.singletonList(product), new Vulnerability("CVE-2023-12345"), Status.not_affected);
        statement.setJustification(Justification.inline_mitigations_already_exist);
        statement.setImpactStatement("Included git is mitigated against CVE-2023-12345!");
        document.setStatements(Collections.singletonList(statement));

        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        try {
            System.out.println(objectMapper.writeValueAsString(document));
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
    }

}
```

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-a06f9de1ad1b1e555a33b2d0c1e7e6ecc4dc1800ff457c61ea09d8e97670d2a3",
  "author": "Wolfi J. Inkinson",
  "timestamp": "2023-09-15T13:13:44.167427-06:00",
  "version": 1,
  "role": "Senior VEXing Engineer",
  "statements": [
    {
      "products": [
        {
          "@id": "pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb"
        }
      ],
      "vulnerability": {
        "name": "CVE-2023-12345"
      },
      "status": "not_affected",
      "justification": "inline_mitigations_already_exist",
      "impact_statement": "Included git is mitigated against CVE-2023-12345!"
    }
  ]
}
```
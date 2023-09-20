package dev.samsanders.openvex;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.time.OffsetDateTime;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

public class SerializationTests {

    @Test
    void serialize_document() throws IOException, MalformedPackageURLException {
        Document document = new Document(Document.DEFAULT_CONTEXT, URI.create(
                "https://openvex.dev/docs/public/vex-2e67563e128250cbcb3e98930df948dd053e43271d70dc50cfa22d57e03fe96f"),
                "Spring Builds <spring-builds@users.noreply.github.com>");
        document.setRole("Project Release Bot");
        document.setTooling("jvex/0.0.1");
        document.setTimestamp(OffsetDateTime.parse("2023-01-17T01:07:16.85347963Z"));

        Vulnerability vulnerability = new Vulnerability("CVE-2021-44228");
        vulnerability.setId(URI.create("https://nvd.nist.gov/vuln/detail/CVE-2021-44228"));
        vulnerability.setDescription("Remote code injection in Log4j");
        vulnerability.setAliases(Collections.singletonList("GHSA-jfh8-c2jp-5v3q"));

        Product product = new Product(URI.create("pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3"));
        Identifiers identifiers = new Identifiers(new PackageURL("pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3"));
        product.setIdentifiers(identifiers);
        Hashes hashes = new Hashes();
        hashes.setSha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        product.setHashes(hashes);
        Statement statement = new Statement(Collections.singletonList(product), vulnerability, Status.not_affected);
        statement.setJustification(Justification.vulnerable_code_not_in_execute_path);
        statement.setImpactStatement("Spring Boot users are only affected by this vulnerability if they have switched the default logging system to Log4J2. The log4j-to-slf4j and log4j-api jars that we include in spring-boot-starter-logging cannot be exploited on their own. Only applications using log4j-core and including user input in log messages are vulnerable.");
        document.setStatements(Collections.singletonList(statement));
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

        String actual = objectMapper.writeValueAsString(document);

        assertEquals(objectMapper.readTree(
                        """
                                {
                                        "@context": "https://openvex.dev/ns/v0.2.0",
                                        "@id": "https://openvex.dev/docs/public/vex-2e67563e128250cbcb3e98930df948dd053e43271d70dc50cfa22d57e03fe96f",
                                        "author": "Spring Builds <spring-builds@users.noreply.github.com>",
                                        "timestamp": "2023-01-17T01:07:16.85347963Z",
                                        "version": 1,
                                        "role": "Project Release Bot",
                                        "tooling": "jvex/0.0.1",
                                        "statements": [
                                          {
                                            "vulnerability": {
                                              "name": "CVE-2021-44228",
                                              "description": "Remote code injection in Log4j",
                                              "aliases": ["GHSA-jfh8-c2jp-5v3q"],
                                              "@id": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                                            },
                                            "products": [
                                              {
                                                "@id": "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3",
                                                "identifiers": {
                                                  "purl": "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3"
                                                },
                                                "hashes": {
                                                  "sha-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                                                }
                                              }
                                            ],
                                            "status": "not_affected",
                                            "justification": "vulnerable_code_not_in_execute_path",
                                            "impact_statement": "Spring Boot users are only affected by this vulnerability if they have switched the default logging system to Log4J2. The log4j-to-slf4j and log4j-api jars that we include in spring-boot-starter-logging cannot be exploited on their own. Only applications using log4j-core and including user input in log messages are vulnerable."
                                          }
                                        ]
                                      }
                                        """),
                objectMapper.readTree(actual));
    }

    @Test
    void not_affected_requires_justification() {
        Document document = new Document(Document.DEFAULT_CONTEXT,
                URI.create("https://openvex.dev/docs/example/vex-1ec2552cd0a46"),
                "some author");
        document.setStatements(Collections.singletonList(new Statement(Collections.singletonList(new Product(URI.create("pkg:apk/wolfi/product@1.23.0-r1?arch=armv7"))), new Vulnerability("some vulerability"),
                Status.not_affected)));
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

        assertThrows(IOException.class, () -> objectMapper.writeValueAsString(document));
    }

    @Test
    void affected_requires_action_statement() {
        Document document = new Document(Document.DEFAULT_CONTEXT,
                URI.create("https://openvex.dev/docs/example/vex-1ec2552cd0a46"),
                "some author");
        document.setStatements(Collections.singletonList(new Statement(Collections.singletonList(new Product(URI.create("pkg:apk/wolfi/product@1.23.0-r1?arch=armv7"))), new Vulnerability("some vulerability"),
                Status.affected)));
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

        assertThrows(IOException.class, () -> {
            objectMapper.writeValueAsString(document);
        });
    }

    @Test
    void action_statement_defaults_action_timestamp() throws IOException {
        Document document = new Document(Document.DEFAULT_CONTEXT,
                URI.create("https://openvex.dev/docs/example/vex-1ec2552cd0a46"),
                "some author");
        Statement statement = new Statement(Collections.singletonList(new Product(URI.create("pkg:apk/wolfi/product@1.23.0-r1?arch=armv7"))), new Vulnerability("some vulerability"),
                Status.affected);
        statement.setActionStatement("some action statement");
        document.setStatements(Collections.singletonList(statement));
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

        String actual = objectMapper.writeValueAsString(document);

        assertNotNull(new ObjectMapper().readTree(actual).get("statements").iterator().next().get("action_statement_timestamp"));
    }

}

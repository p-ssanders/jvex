package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import dev.samsanders.openvex.*;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class OutsidePackageTests {

    @Test
    void generate() throws IOException, MalformedPackageURLException {
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
        vulnerability.setAliases(List.of("GHSA-jfh8-c2jp-5v3q"));

        Statement statement = new Statement(Collections.singletonList(product), vulnerability, Status.not_affected);
        statement.setJustification(Justification.vulnerable_code_not_in_execute_path);
        statement.setImpactStatement("Spring Boot users are only affected by this vulnerability if they have switched the default logging system to Log4J2. " +
                "The log4j-to-slf4j and log4j-api jars that we include in spring-boot-starter-logging cannot be exploited on their own. " +
                "Only applications using log4j-core and including user input in log messages are vulnerable.");
        document.getStatements().add(statement);

        String actual = document.asJson();

        assertNotNull(actual);
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        assertNull(objectMapper.readTree(actual).get("statements").iterator().next().get("products").iterator().next().get("subcomponents"));
        assertNotNull(objectMapper.readTree(actual).get("@id"));
    }

    @Test
    void consume() throws IOException, MalformedPackageURLException {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("documents/example.json").getFile());
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

        Document actual = objectMapper.readValue(file, Document.class);

        assertNotNull(actual);
        assertEquals(URI.create("https://openvex.dev/ns/v0.2.0"), actual.getContext());
        assertEquals(URI.create("https://openvex.dev/docs/public/vex-2e67563e128250cbcb3e98930df948dd053e43271d70dc50cfa22d57e03fe96f"), actual.getId());
        assertEquals("Spring Builds <spring-builds@users.noreply.github.com>", actual.getAuthor());
        assertEquals("Project Release Bot", actual.getRole());
        assertEquals(OffsetDateTime.parse("2023-01-16T19:07:16.853479631-06:00"), actual.getTimestamp());
        assertEquals(1, actual.getVersion());
        assertEquals("jvex/0.1.0", actual.getTooling());
        assertFalse(actual.getStatements().isEmpty());
        assertEquals(OffsetDateTime.parse("2023-09-06T00:05:18.123456789-05:00"), actual.getLastUpdated());
        assertFalse(actual.getStatements().isEmpty());

        Vulnerability expectedVulnerability = new Vulnerability("CVE-2021-44228");
        expectedVulnerability.setId(URI.create("https://nvd.nist.gov/vuln/detail/CVE-2021-44228"));
        expectedVulnerability.setDescription("Remote code injection in Log4j");
        expectedVulnerability.setAliases(Collections.singletonList("GHSA-jfh8-c2jp-5v3q"));

        Statement actualStatement = actual.getStatements().iterator().next();
        assertEquals(expectedVulnerability, actualStatement.getVulnerability());
        assertEquals(Status.not_affected, actualStatement.getStatus());
        assertEquals(Justification.vulnerable_code_not_in_execute_path, actualStatement.getJustification());

        Product expectedProduct = new Product(URI.create("pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3"));
        expectedProduct.setIdentifiers(new Identifiers(new PackageURL("pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3")));
        Hashes expectedHashes = new Hashes();
        expectedHashes.setSha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        expectedProduct.setHashes(expectedHashes);
        assertEquals(expectedProduct, actualStatement.getProducts().iterator().next());
    }

}

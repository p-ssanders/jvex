package dev.samsanders.openvex;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.List;

import static dev.samsanders.openvex.Document.DEFAULT_CONTEXT;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CanonicalDocumentIdGeneratorTest {
    @Test
    void getCanonicalRepresentation() throws MalformedPackageURLException {
        Document document = getTestDocument();
        CanonicalDocumentIdGenerator canonicalDocumentIdGenerator = new CanonicalDocumentIdGenerator();

        String actual = canonicalDocumentIdGenerator.getCanonicalRepresentation(document);

        assertEquals("1673917636:1:Spring Builds <spring-builds@users.noreply.github.com>:https://nvd.nist.gov/vuln/detail/CVE-2021-44228:CVE-2021-44228:GHSA-jfh8-c2jp-5v3q:not_affected:vulnerable_code_not_in_execute_path:1673917636:pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb:sha-256@e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:purl@pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb", actual);
    }

    @Test
    void generate() throws MalformedPackageURLException {
        Document document = getTestDocument();
        CanonicalDocumentIdGenerator canonicalDocumentIdGenerator = new CanonicalDocumentIdGenerator();
        String canonicalRepresentation = canonicalDocumentIdGenerator.getCanonicalRepresentation(document);
        String sha256 = DigestUtils.sha256Hex(canonicalRepresentation);

        URI actual = canonicalDocumentIdGenerator.generate(document);

        assertEquals(URI.create("https://openvex.dev/docs/public/vex-%s".formatted(sha256)), actual);
    }

    private static Document getTestDocument() throws MalformedPackageURLException {
        Document document = new Document(DEFAULT_CONTEXT, null, "Spring Builds <spring-builds@users.noreply.github.com>");
        document.setRole("Project Release Bot");
        document.setTimestamp(OffsetDateTime.parse("2023-01-16T19:07:16.853479631-06:00"));
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
        statement.setImpactStatement("Spring Boot users are only affected by this vulnerability if they have switched the default logging system to Log4J2. The log4j-to-slf4j and log4j-api jars that we include in spring-boot-starter-logging cannot be exploited on their own. Only applications using log4j-core and including user input in log messages are vulnerable.");
        document.setStatements(Collections.singletonList(statement));

        return document;
    }
}
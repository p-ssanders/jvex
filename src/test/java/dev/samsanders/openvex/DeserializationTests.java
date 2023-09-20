package dev.samsanders.openvex;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.time.OffsetDateTime;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class DeserializationTests {

    ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Test
    void deserialize_specExample() throws IOException, MalformedPackageURLException {
        File file = getFile("documents/example.json");

        Document actual = objectMapper.readValue(file, Document.class);

        assertNotNull(actual);
        assertEquals(URI.create("https://openvex.dev/ns/v0.2.0"), actual.getContext());
        assertEquals(URI.create("https://openvex.dev/docs/public/vex-2e67563e128250cbcb3e98930df948dd053e43271d70dc50cfa22d57e03fe96f"), actual.getId());
        assertEquals("Spring Builds <spring-builds@users.noreply.github.com>", actual.getAuthor());
        assertEquals("Project Release Bot", actual.getRole());
        assertEquals(OffsetDateTime.parse("2023-01-16T19:07:16.853479631-06:00"), actual.getTimestamp());
        assertEquals(1, actual.getVersion());
        assertEquals("jvex/0.0.1", actual.getTooling());
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

    @Test
    void deserialize_invalid() {
        File file = getFile("documents/invalid.json");

        assertThrows(IOException.class, () -> objectMapper.readValue(file, Document.class));
    }

    @Test
    void deserialize_statement_optional() throws IOException {
        File file = getFile("documents/with-statements-optional.json");

        Statement actual = objectMapper.readValue(file, Document.class).getStatements().iterator().next();

        assertEquals(URI.create("https://openvex.dev/docs/example/vex-1ec4574ef2c68"), actual.getId());
        assertEquals(1, actual.getVersion());
        assertEquals(OffsetDateTime.parse("2023-09-06T22:07:45.123456789-05:00"), actual.getTimestamp());
        assertEquals(OffsetDateTime.parse("2023-09-06T22:09:21.123456789-05:00"), actual.getLastUpdated());
        assertEquals("some-supplier", actual.getSupplier());
        assertEquals("some status notes", actual.getStatusNotes());
    }

    @Test
    void deserialize_statement_not_affected() throws IOException {
        File file = getFile("documents/with-statements-not_affected.json");

        Statement actual = objectMapper.readValue(file, Document.class).getStatements().iterator().next();

        assertEquals(Status.not_affected, actual.getStatus());
        assertEquals(Justification.component_not_present, actual.getJustification());
        assertEquals("some impact statement", actual.getImpactStatement());
    }

    @Test
    void deserialize_statement_affected() throws IOException {
        File file = getFile("documents/with-statements-affected.json");

        Statement actual = objectMapper.readValue(file, Document.class).getStatements().iterator().next();

        assertEquals(Status.affected, actual.getStatus());
        assertEquals("some action statement", actual.getActionStatement());
        assertEquals(OffsetDateTime.parse("2023-09-06T22:25:47.123456789-05:00"), actual.getActionStatementTimestamp());
    }

    @Test
    void deserialize_product()
            throws IOException, MalformedPackageURLException {
        File file = getFile("documents/with-products.json");

        Product actual = objectMapper.readValue(file, Document.class).getStatements().iterator().next().getProducts().iterator().next();

        assertNotNull(actual);
        assertEquals(URI.create("pkg:apk/wolfi/product@1.23.0-r1?arch=armv7"), actual.getId());
        assertEquals(new PackageURL("pkg:maven/org.apache.logging.log4j/log4j-core@2.4"),
                actual.getIdentifiers().getPackageURL());
        assertEquals("402fa523b96591d4450ace90e32d9f779fcfd938903e1c5bf9d3701860b8f856",
                actual.getHashes().getSha256());
        assertEquals(
                "d2eb65b083923d90cf55111c598f81d3d9c66f4457dfd173f01a6b7306f3b222541be42a35fe47191a9ca00e017533e8c07ca192bd22954e125557c72d2a3178",
                actual.getHashes().getSha512());
        assertNotNull(actual.getSubcomponents().iterator().next());

    }

    @Test
    void deserialize_vulnerability() throws IOException {
        File file = getFile("documents/with-vulnerability.json");

        Vulnerability actual = objectMapper.readValue(file, Document.class).getStatements().iterator().next().getVulnerability();

        assertEquals(actual.getName(), "CVE-2023-12345");
        assertEquals(URI.create("https://openvex.dev/docs/example/vex-9fb3463de1b57"), actual.getId());
        assertEquals("some description", actual.getDescription());
        assertEquals(Collections.singletonList("some alias"), actual.getAliases());

    }

    private File getFile(String name) {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource(name).getFile());
        return file;
    }
}
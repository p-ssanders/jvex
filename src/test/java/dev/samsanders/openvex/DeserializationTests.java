package dev.samsanders.openvex;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.time.OffsetDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DeserializationTests {

    @Test
    void invalid_no_context() {
        File file = getFile("documents/invalid/no-context.json");

        assertThrows(IOException.class, () -> Document.fromFile(file));
    }

    @Test
    void invalid_no_id() {
        File file = getFile("documents/invalid/no-id.json");

        assertThrows(IOException.class, () -> Document.fromFile(file));
    }

    @Test
    void invalid_no_author() {
        File file = getFile("documents/invalid/no-author.json");

        assertThrows(IOException.class, () -> Document.fromFile(file));
    }

    @Test
    void invalid_bad_timestamp() {
        File file = getFile("documents/invalid/bad-timestamp.json");

        assertThrows(IOException.class, () -> Document.fromFile(file));
    }

    @Test
    void invalid_no_version() {
        File file = getFile("documents/invalid/no-version.json");

        assertThrows(IOException.class, () -> Document.fromFile(file));
    }

    @Test
    void invalid_no_statements() {
        File file = getFile("documents/invalid/no-statements.json");

        assertThrows(IOException.class, () -> Document.fromFile(file));
    }

    @Test
    void statement_with_optional_fields() throws IOException {
        File file = getFile("documents/with-statements-optional.json");

        Statement actual = Document.fromFile(file).getStatements().iterator().next();

        assertEquals(URI.create("https://openvex.dev/docs/example/vex-1ec4574ef2c68"), actual.getId());
        assertEquals(1, actual.getVersion());
        assertEquals(OffsetDateTime.parse("2023-09-06T22:07:45.123456789-05:00"), actual.getTimestamp());
        assertEquals(OffsetDateTime.parse("2023-09-06T22:09:21.123456789-05:00"), actual.getLastUpdated());
        assertEquals("some-supplier", actual.getSupplier());
        assertEquals("some status notes", actual.getStatusNotes());
        assertEquals(URI.create("pkg:apk/wolfi/git@2.39.0-r1?arch=armv7"), actual.getProducts().iterator().next().getSubcomponents().iterator().next().getId());
    }

    @Test
    void author_role_cannot_be_set_on_deserialized_documents() throws IOException {
        File file = getFile("documents/example.json");
        Document document = Document.fromFile(file);

        assertThrows(IllegalStateException.class, () -> document.setRole("new role"));
    }

    private File getFile(String name) {
        ClassLoader classLoader = getClass().getClassLoader();
        return new File(classLoader.getResource(name).getFile());
    }
}
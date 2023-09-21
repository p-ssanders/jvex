package dev.samsanders.openvex;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URI;

import static dev.samsanders.openvex.Document.DEFAULT_CONTEXT;
import static org.junit.jupiter.api.Assertions.*;

class DocumentTest {

    @Test
    void context_cannot_be_null() {
        assertThrows(IllegalArgumentException.class, () -> {
            new Document(null, URI.create("http://some.uri"), "some author");
        });
    }

    @Test
    void author_cannot_be_null() {
        assertThrows(IllegalArgumentException.class, () -> {
            new Document(DEFAULT_CONTEXT, URI.create("http://some.uri"), null);
        });
    }

    @Test
    void author_role_cannot_be_set_on_deserialized_documents() throws IOException {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("documents/example.json").getFile());
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        Document document = objectMapper.readValue(file, Document.class);

        assertThrows(IllegalStateException.class, () -> document.setRole("new role"));
    }

    @Test
    void version_can_be_incremented() {
        Document document = new Document(DEFAULT_CONTEXT, URI.create("http://some.uri"), "some-author");

        document.incrementVersion();

        assertEquals(2, document.getVersion());
    }

    @Test
    void documents_created_with_jvex_specify_tooling() {
        Document document = new Document(DEFAULT_CONTEXT, URI.create("http://some.uri"), "some-author");

        assertEquals("jvex/1.0.0", document.getTooling());
    }

    @Test
    void generateId_updates_id() throws IOException {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("documents/example.json").getFile());
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        Document document = objectMapper.readValue(file, Document.class);

        document.generateId(document1 -> {
            assertNotNull(document1);
            return URI.create("http://some.document/id");
        });

        assertEquals(URI.create("http://some.document/id"), document.getId());
    }

}
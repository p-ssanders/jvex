package dev.samsanders.openvex;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static dev.samsanders.openvex.Document.DEFAULT_CONTEXT;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

}
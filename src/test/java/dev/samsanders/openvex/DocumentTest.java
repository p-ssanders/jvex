package dev.samsanders.openvex;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertThrows;

class DocumentTest {

    @Test
    void context_cannot_be_null() {
        assertThrows(IllegalArgumentException.class, () -> {
            new Document(null, URI.create("http://some.uri"), "some author");
        });
    }

}
package dev.samsanders.openvex;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ProductTest {

    @Test
    void id_cannot_be_null() {
        assertThrows(IllegalArgumentException.class, () -> new Product(null));
    }

    @Test
    void can_add_subcomponents() {
        Product product = new Product(URI.create("http://some.uri"));

        product.getSubcomponents().add(new Product(URI.create("http://other.uri")));

        assertEquals(Collections.singletonList(new Product(URI.create("http://other.uri"))), product.getSubcomponents());
    }

}
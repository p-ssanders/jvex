package com.example;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import dev.samsanders.openvex.*;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class OutsidePackageTests {

    @Test
    void readmeTest() throws JsonProcessingException {
        Document document = new Document("https://openvex.dev/ns/v0.2.0",
                URI.create("https://openvex.dev/docs/public/vex-a06f9de1ad1b1e555a33b2d0c1e7e6ecc4dc1800ff457c61ea09d8e97670d2a3"),
                "Wolfi J. Inkinson");
        document.setRole("Senior VEXing Engineer");
        Product product = new Product(URI.create("pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb"));
        Statement statement = new Statement(Collections.singletonList(product), new Vulnerability("CVE-2023-12345"), Status.not_affected);
        statement.setJustification(Justification.vulnerable_code_not_in_execute_path);
        statement.setImpactStatement("Automated dataflow analysis and manual code review indicates that the vulnerable code is not reachable, either directly or indirectly.");
        document.setStatements(Collections.singletonList(statement));

        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        assertNotNull(objectMapper.writeValueAsString(document));
    }
}

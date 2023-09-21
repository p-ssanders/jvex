package dev.samsanders.openvex;

import java.net.URI;

public interface DocumentIdGenerator {

    URI generate(Document document);
}

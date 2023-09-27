package dev.samsanders.openvex;

import java.net.URI;

interface DocumentIdGenerator {

    URI generate(Document document);
}

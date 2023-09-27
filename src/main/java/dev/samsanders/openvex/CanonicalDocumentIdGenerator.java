package dev.samsanders.openvex;

import org.apache.commons.codec.digest.DigestUtils;

import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Map;

final class CanonicalDocumentIdGenerator implements DocumentIdGenerator {

    /**
     * Generate an ID for the Document based on the "canonicalization hash."
     * Generation algorithm re-implemented from go-vex's VEX.CanonicalHash
     * to produce the same hashes given the same document
     * @see <a href="https://github.com/openvex/go-vex">go-vex</a>
     */
    @Override
    public URI generate(Document document) {
        String canonicalRepresentation = getCanonicalRepresentation(document);
        String canonicalHash = getCanonicalHash(canonicalRepresentation);
        String stringBuilder = "https://openvex.dev/docs/public/vex-%s".formatted(canonicalHash);

        return URI.create(stringBuilder);
    }

    String getCanonicalRepresentation(Document document) {
        StringBuilder stringBuilder = new StringBuilder();

        // 1. Start with the document date. In unixtime to avoid format variance.
        stringBuilder.append("%d".formatted(document.getTimestamp().toEpochSecond()));

        // 2. Document version
        stringBuilder.append(":%d".formatted(document.getVersion()));

        // 3. Author identity
        stringBuilder.append(":%s".formatted(document.getAuthor()));

        // 4. Sort the statements
        ArrayList<Statement> statements = new ArrayList<>(document.getStatements());
        statements.sort(new StatementComparator(document));

        // 5. Now add the data from each statement
        for (Statement statement : statements) {
            // 5a. Vulnerability
            Vulnerability vulnerability = statement.getVulnerability();
            if (null != vulnerability.getId())
                stringBuilder.append(":%s".formatted(vulnerability.getId()));
            stringBuilder.append(":%s".formatted(vulnerability.getName()));
            if (null != vulnerability.getAliases())
                stringBuilder.append(":%s".formatted(String.join(":", vulnerability.getAliases())));

            // 5b. Status + Justification
            stringBuilder.append(":%s:%s".formatted(statement.getStatus(), statement.getJustification()));

            // 5c. Statement time, in unixtime. If it exists, if not the doc's
            if (null != statement.getTimestamp()) {
                stringBuilder.append(":%d".formatted(statement.getTimestamp().toEpochSecond()));
            } else {
                stringBuilder.append(":%d".formatted(document.getTimestamp().toEpochSecond()));
            }

            // 5d. Sorted product strings
            ArrayList<String> productStrings = new ArrayList<>();
            for (Product product : statement.getProducts()) {

                StringBuilder productString = new StringBuilder(componentString(product));
                if (null != product.getSubcomponents()) {
                    for (Component subcomponent : product.getSubcomponents())
                        productString.append(componentString(subcomponent));
                }

                productStrings.add(productString.toString());
            }
            productStrings.sort(String::compareTo);
            stringBuilder.append("%s".formatted(String.join(":", productStrings)));
        }

        return stringBuilder.toString();
    }

    private String getCanonicalHash(String canonicalRepresentation) {
        // 6. Hash the string in sha256 and return
        return DigestUtils.sha256Hex(canonicalRepresentation);
    }

    private String componentString(Component component) {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append(":%s".formatted(component.getId()));
        if (null != component.getHashes()) {
            Map<String, String> hashesAsMap = component.getHashes().asMap();
            for (String algo : hashesAsMap.keySet())
                stringBuilder.append(":%s@%s".formatted(algo, hashesAsMap.get(algo)));
        }

        if (null != component.getIdentifiers())
            stringBuilder.append(":%s@%s".formatted("purl", component.getIdentifiers().getPackageURL().canonicalize().replace("%3A", ":")));

        return stringBuilder.toString();
    }

    private record StatementComparator(Document document) implements Comparator<Statement> {

        @Override
        public int compare(Statement s1, Statement s2) {
            // If vulnerabilities aren't the same, then sort alphabetically
            if (!s1.getVulnerability().getName().equals(s2.getVulnerability().getName())) {
                return s1.getVulnerability().getName().compareTo(s2.getVulnerability().getName());
            }

            if (null == s1.getTimestamp()) {
                s1.setTimestamp(document.getTimestamp());
            }

            if (null == s2.getTimestamp()) {
                s2.setTimestamp(document.getTimestamp());
            }

            if (s1.getTimestamp().isBefore(s2.getTimestamp())) {
                return -1;
            } else if (s1.getTimestamp().isAfter(s2.getTimestamp())) {
                return 1;
            }

            return 0;
        }
    }
}

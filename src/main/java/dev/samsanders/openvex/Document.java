package dev.samsanders.openvex;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Objects;

import static com.fasterxml.jackson.annotation.JsonFormat.Feature.ADJUST_DATES_TO_CONTEXT_TIME_ZONE;

/**
 * A data structure that groups together one or more VEX statements
 */
@JsonInclude(Include.NON_NULL)
public final class Document {

    public static final URI DEFAULT_CONTEXT = URI.create("https://openvex.dev/ns/v0.2.0");
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().registerModule(new JavaTimeModule());
    private static final ObjectWriter OBJECT_WRITER = OBJECT_MAPPER.writer().withDefaultPrettyPrinter();
    private static final ObjectReader OBJECT_READER = OBJECT_MAPPER.reader();

    /**
     * The URL linking to the OpenVEX context definition. The URL is structured as
     * https://openvex.dev/ns/v[version], where [version] represents the specific
     * version number, such as v0.2.0.
     */
    @JsonProperty(value = "@context", required = true)
    private final URI context;

    /**
     * The IRI identifying the VEX document.
     */
    @JsonProperty(value = "@id", required = true)
    private URI id;

    /**
     * Author is the identifier for the author of the VEX statement.
     */
    private final String author;

    /**
     * Timestamp defines the time at which the document was issued.
     */
    @JsonFormat(without = {ADJUST_DATES_TO_CONTEXT_TIME_ZONE})
    private OffsetDateTime timestamp;

    /**
     * Version is the document version.
     */
    private Integer version;

    /**
     * role describes the role of the document author.
     */
    private String role;

    /**
     * Date of last modification to the document.
     */
    @JsonProperty("last_updated")
    @JsonFormat(without = {ADJUST_DATES_TO_CONTEXT_TIME_ZONE})
    private OffsetDateTime lastUpdated;

    /**
     * Tooling expresses how the VEX document and contained VEX statements were
     * generated.
     */
    private String tooling;

    /**
     * A statement is an assertion made by the document's author about the impact a
     * vulnerability has on one or more software "products".
     */
    private Collection<Statement> statements;

    @JsonIgnore
    private transient boolean deserialized;

    @JsonCreator
    Document(@JsonProperty(value = "@context", required = true) URI context,
             @JsonProperty(value = "@id", required = true) URI id,
             @JsonProperty(value = "author", required = true) String author,
             @JsonProperty(value = "timestamp", required = true) OffsetDateTime timestamp,
             @JsonProperty(value = "version", required = true) Integer version,
             @JsonProperty(value = "statements", required = true) Collection<Statement> statements) {
        this.context = context;
        this.id = id;
        this.author = author;
        this.timestamp = timestamp;
        this.version = version;
        if (statements.isEmpty()) {
            throw new IllegalArgumentException("Document must have statements");
        }
        this.statements = statements;
        this.deserialized = true;
    }

    Document(URI context, URI id, String author) {
        if (null == context) {
            throw new IllegalArgumentException("Context cannot be null");
        }
        if (null == author) {
            throw new IllegalArgumentException("Author cannot be null");
        }
        this.context = context;
        this.id = id;
        this.author = author;
        this.timestamp = OffsetDateTime.now();
        this.version = 1;
        this.tooling = "jvex/1.0.0";
        this.statements = new ArrayList<>();
    }

    public Document(String author) {
        this(DEFAULT_CONTEXT, null, author);
    }

    public static Document fromFile(File json) throws IOException {
        return OBJECT_READER.readValue(json, Document.class);
    }

    public URI getContext() {
        return this.context;
    }

    public URI getId() {
        return id;
    }

    public String getAuthor() {
        return this.author;
    }

    public OffsetDateTime getTimestamp() {
        return this.timestamp;
    }

    public Integer getVersion() {
        return this.version;
    }

    public String getRole() {
        return this.role;
    }

    public OffsetDateTime getLastUpdated() {
        return this.lastUpdated;
    }

    public String getTooling() {
        return this.tooling;
    }

    public Collection<Statement> getStatements() {
        return this.statements;
    }

    @JsonGetter("statements")
    Collection<Statement> serializeStatements() {
        if (null == this.statements || this.statements.isEmpty()) {
            throw new IllegalStateException("Document must have statements");
        }
        return this.statements;
    }

    void generateId(DocumentIdGenerator documentIdGenerator) {
        this.id = documentIdGenerator.generate(this);
    }

    public void generateId() {
        this.generateId(new CanonicalDocumentIdGenerator());
    }

    public void incrementVersion() {
        this.version++;
    }

    @JsonSetter("role")
    void deserializeRole(String role) {
        this.role = role;
    }

    public void setRole(String role) {
        if (this.deserialized) {
            throw new IllegalStateException("Cannot set author role on existing documents");
        }
        this.role = role;
    }

    public void setTooling(String tooling) {
        this.tooling = tooling;
    }

    @JsonGetter("timestamp")
    String serializeTimestamp() {
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(Objects.requireNonNullElseGet(this.timestamp, OffsetDateTime::now));
    }

    void setTimestamp(OffsetDateTime timestamp) {
        this.timestamp = timestamp;
    }

    @JsonGetter("last_updated")
    String serializeLastUpdated() {
        if (null == this.lastUpdated) return null;
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(this.lastUpdated);
    }

    public void setLastUpdated(OffsetDateTime lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    void setStatements(Collection<Statement> statements) {
        this.statements = statements;
    }

    public String asJson() throws IOException {
        return OBJECT_WRITER.writeValueAsString(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Document document = (Document) o;
        return Objects.equals(getContext(), document.getContext()) && Objects.equals(getId(), document.getId()) && Objects.equals(getAuthor(), document.getAuthor()) && Objects.equals(getTimestamp(), document.getTimestamp()) && Objects.equals(getVersion(), document.getVersion()) && Objects.equals(getRole(), document.getRole()) && Objects.equals(getLastUpdated(), document.getLastUpdated()) && Objects.equals(getTooling(), document.getTooling()) && Objects.equals(getStatements(), document.getStatements());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getContext(), getId(), getAuthor(), getTimestamp(), getVersion(), getRole(), getLastUpdated(), getTooling(), getStatements());
    }

    @Override
    public String toString() {
        return "Document{" +
                "context='" + context + '\'' +
                ", id=" + id +
                ", author='" + author + '\'' +
                ", timestamp=" + timestamp +
                ", version=" + version +
                ", role='" + role + '\'' +
                ", lastUpdated=" + lastUpdated +
                ", tooling='" + tooling + '\'' +
                ", statements=" + statements +
                '}';
    }
}

package dev.samsanders.openvex;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import java.net.URI;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.Objects;

import static com.fasterxml.jackson.annotation.JsonFormat.Feature.ADJUST_DATES_TO_CONTEXT_TIME_ZONE;

/**
 * An assertion made by the document's author about the impact a vulnerability has on one or more software "products"
 */
@JsonInclude(Include.NON_NULL)
public final class Statement {

    /**
     * A struct identifying the vulnerability.
     */
    @JsonProperty(value = "vulnerability", required = true)
    private final Vulnerability vulnerability;

    /**
     * List of product structs that the statement applies to.
     */
    @JsonProperty(value = "products", required = true)
    private final Collection<Product> products;

    /**
     * Status labels inform the impact of a vulnerability in the products listed in
     * a statement
     */
    @JsonProperty(value = "status", required = true)
    private final Status status;

    /**
     * Optional IRI identifying the statement to make it externally referenceable.
     */
    @JsonProperty("@id")
    private URI id;

    /**
     * Optional integer representing the statement's version number.
     */
    private Integer version;

    /**
     * Timestamp is the time at which the information expressed in the Statement was
     * known to be true.
     */
    @JsonFormat(without = {ADJUST_DATES_TO_CONTEXT_TIME_ZONE})
    private OffsetDateTime timestamp;

    /**
     * Timestamp when the statement was last updated.
     */
    @JsonProperty("last_updated")
    @JsonFormat(without = {ADJUST_DATES_TO_CONTEXT_TIME_ZONE})
    private OffsetDateTime lastUpdated;

    /**
     * Supplier of the product or subcomponent.
     */
    private String supplier;

    /**
     * A statement MAY convey information about how status was determined and MAY
     * reference other VEX information.
     */
    @JsonProperty("status_notes")
    private String statusNotes;

    /**
     * For statements conveying a not_affected status, a VEX statement MUST include
     * either a status justification or an impact_statement informing why the
     * product is not affected by the vulnerability.
     */
    private Justification justification;

    /**
     * An impact statement is a free form text containing a description of why the
     * vulnerability cannot be exploited.
     */
    @JsonProperty("impact_statement")
    private String impactStatement;

    /**
     * For a statement with "affected" status, a VEX statement MUST include a
     * statement that SHOULD describe actions to remediate or mitigate the
     * vulnerability.
     */
    @JsonProperty("action_statement")
    private String actionStatement;

    /**
     * The timestamp when the action statement was issued.
     */
    @JsonProperty("action_statement_timestamp")
    @JsonFormat(without = {ADJUST_DATES_TO_CONTEXT_TIME_ZONE})
    private OffsetDateTime actionStatementTimestamp;

    @JsonCreator
    public Statement(@JsonProperty(value = "products", required = true) Collection<Product> products,
                     @JsonProperty(value = "vulnerability", required = true) Vulnerability vulnerability,
                     @JsonProperty(value = "status", required = true) Status status) {
        this.vulnerability = vulnerability;
        this.products = products;
        this.status = status;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public Collection<Product> getProducts() {
        return products;
    }

    public Status getStatus() {
        return status;
    }

    public URI getId() {
        return id;
    }

    public void setId(URI id) {
        this.id = id;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public OffsetDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(OffsetDateTime timestamp) {
        this.timestamp = timestamp;
    }

    @JsonGetter("timestamp")
    String serializeTimestamp() {
        if (null == this.timestamp) return null;
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(this.timestamp);
    }

    public OffsetDateTime getLastUpdated() {
        return lastUpdated;
    }

    @JsonGetter("last_updated")
    public String serializeLastUpdated() {
        if (null == this.lastUpdated) return null;
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(this.lastUpdated);
    }

    public void setLastUpdated(OffsetDateTime lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    public String getSupplier() {
        return supplier;
    }

    public void setSupplier(String supplier) {
        this.supplier = supplier;
    }

    public String getStatusNotes() {
        return statusNotes;
    }

    public void setStatusNotes(String statusNotes) {
        this.statusNotes = statusNotes;
    }

    public Justification getJustification() {
        if (this.status == Status.not_affected && this.justification == null) {
            throw new IllegalStateException("For statements conveying a not_affected status, a VEX statement MUST include either a status justification or an impact_statement informing why the product is not affected by the vulnerability");
        }
        return justification;
    }

    public void setJustification(Justification justification) {
        this.justification = justification;
    }

    public String getImpactStatement() {
        return impactStatement;
    }

    public void setImpactStatement(String impactStatement) {
        this.impactStatement = impactStatement;
    }

    public String getActionStatement() {
        if (this.status == Status.affected && this.actionStatement == null) {
            throw new IllegalStateException(("For a statement with \"affected\" status, a VEX statement MUST include a statement that SHOULD describe actions to remediate or mitigate the vulnerability."));
        }

        return actionStatement;
    }

    /**
     * Sets the action_statement field
     * Also sets the action_statement_timestamp field to now
     *
     * @param actionStatement the action statement
     */
    public void setActionStatement(String actionStatement) {
        this.actionStatement = actionStatement;
        this.actionStatementTimestamp = OffsetDateTime.now();
    }

    public OffsetDateTime getActionStatementTimestamp() {
        return actionStatementTimestamp;
    }

    @JsonGetter("action_statement_timestamp")
    public String serializeActionStatementTimestamp() {
        if (null == this.actionStatementTimestamp) return null;
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(this.actionStatementTimestamp);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Statement statement = (Statement) o;
        return Objects.equals(getVulnerability(), statement.getVulnerability()) && Objects.equals(getProducts(), statement.getProducts()) && getStatus() == statement.getStatus() && Objects.equals(getId(), statement.getId()) && Objects.equals(getVersion(), statement.getVersion()) && Objects.equals(getTimestamp(), statement.getTimestamp()) && Objects.equals(getLastUpdated(), statement.getLastUpdated()) && Objects.equals(getSupplier(), statement.getSupplier()) && Objects.equals(getStatusNotes(), statement.getStatusNotes()) && getJustification() == statement.getJustification() && Objects.equals(getImpactStatement(), statement.getImpactStatement()) && Objects.equals(getActionStatement(), statement.getActionStatement()) && Objects.equals(getActionStatementTimestamp(), statement.getActionStatementTimestamp());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getVulnerability(), getProducts(), getStatus(), getId(), getVersion(), getTimestamp(), getLastUpdated(), getSupplier(), getStatusNotes(), getJustification(), getImpactStatement(), getActionStatement(), getActionStatementTimestamp());
    }

    @Override
    public String toString() {
        return "Statement{" +
                "vulnerability=" + vulnerability +
                ", products=" + products +
                ", status=" + status +
                ", id=" + id +
                ", version=" + version +
                ", timestamp=" + timestamp +
                ", lastUpdated=" + lastUpdated +
                ", supplier='" + supplier + '\'' +
                ", statusNotes='" + statusNotes + '\'' +
                ", justification=" + justification +
                ", impactStatement='" + impactStatement + '\'' +
                ", actionStatement='" + actionStatement + '\'' +
                ", actionStatementTimestamp=" + actionStatementTimestamp +
                '}';
    }
}

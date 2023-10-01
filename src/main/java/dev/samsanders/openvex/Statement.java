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
 * An assertion made by the document's author about the impact a vulnerability has on one or more software products
 */
@JsonInclude(Include.NON_NULL)
public final class Statement {

    private final Vulnerability vulnerability;

    private final Collection<Product> products;

    private final Status status;

    @JsonProperty("@id")
    private URI id;

    private Integer version;

    @JsonFormat(without = {ADJUST_DATES_TO_CONTEXT_TIME_ZONE})
    private OffsetDateTime timestamp;

    @JsonProperty("last_updated")
    @JsonFormat(without = {ADJUST_DATES_TO_CONTEXT_TIME_ZONE})
    private OffsetDateTime lastUpdated;

    private String supplier;

    @JsonProperty("status_notes")
    private String statusNotes;

    private Justification justification;

    @JsonProperty("impact_statement")
    private String impactStatement;

    @JsonProperty("action_statement")
    private String actionStatement;

    @JsonProperty("action_statement_timestamp")
    @JsonFormat(without = {ADJUST_DATES_TO_CONTEXT_TIME_ZONE})
    private OffsetDateTime actionStatementTimestamp;

    /**
     * Create a statement by providing a list of products, a vulnerability, and a status
     */
    @JsonCreator
    public Statement(@JsonProperty(value = "products", required = true) Collection<Product> products,
                     @JsonProperty(value = "vulnerability", required = true) Vulnerability vulnerability,
                     @JsonProperty(value = "status", required = true) Status status) {
        this.vulnerability = vulnerability;
        this.products = products;
        this.status = status;
    }

    /**
     * Get the struct identifying the vulnerability
     */
    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    /**
     * Get a list of product structs that the statement applies to
     */
    public Collection<Product> getProducts() {
        return products;
    }

    /**
     * Get the status labels that informs the impact of a vulnerability in the products listed in a statement
     */
    public Status getStatus() {
        return status;
    }

    /**
     * Get the optional IRI identifying the statement to make it externally referenceable
     */
    public URI getId() {
        return id;
    }

    /**
     * Get the optional integer representing the statement's version number
     */
    public Integer getVersion() {
        return version;
    }

    /**
     * Get the timestamp at which the information expressed in the Statement was known to be true
     */
    public OffsetDateTime getTimestamp() {
        return timestamp;
    }

    /**
     * Get the timestamp when the statement was last updated
     */
    public OffsetDateTime getLastUpdated() {
        return lastUpdated;
    }

    /**
     * Get the supplier of the product or subcomponent
     */
    public String getSupplier() {
        return supplier;
    }

    /**
     * Get information about how status was determined and possible references to other VEX information
     */
    public String getStatusNotes() {
        return statusNotes;
    }

    /**
     * Get the Justification for statements conveying a not_affected status, informing why the
     * product is not affected by the vulnerability
     */
    public Justification getJustification() {
        if (this.status == Status.not_affected && this.justification == null) {
            throw new IllegalStateException("For statements conveying a not_affected status, a VEX statement MUST include either a status justification or an impact_statement informing why the product is not affected by the vulnerability");
        }
        return justification;
    }

    /**
     * Get the free form text containing a description of why the vulnerability cannot be exploited
     */
    public String getImpactStatement() {
        return impactStatement;
    }

    /**
     * Get the statement that SHOULD describe actions to remediate or mitigate the vulnerability
     * for statements with "affected" status
     */
    public String getActionStatement() {
        if (this.status == Status.affected && this.actionStatement == null) {
            throw new IllegalStateException(("For a statement with \"affected\" status, a VEX statement MUST include a statement that SHOULD describe actions to remediate or mitigate the vulnerability."));
        }

        return actionStatement;
    }

    /**
     * Get the timestamp when the action statement was issued
     */
    public OffsetDateTime getActionStatementTimestamp() {
        return actionStatementTimestamp;
    }

    /**
     * Set the optional IRI identifying the statement to make it externally referenceable
     */
    public void setId(URI id) {
        this.id = id;
    }

    /**
     * Set the optional integer representing the statement's version number
     */
    public void setVersion(Integer version) {
        this.version = version;
    }

    /**
     * Set the timestamp at which the information expressed in the Statement was known to be true
     */
    public void setTimestamp(OffsetDateTime timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Set the timestamp when the statement was last updated
     */
    public void setLastUpdated(OffsetDateTime lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    /**
     * Set the supplier of the product or subcomponent
     */
    public void setSupplier(String supplier) {
        this.supplier = supplier;
    }

    /**
     * Set information about how status was determined and possible references to other VEX information
     */
    public void setStatusNotes(String statusNotes) {
        this.statusNotes = statusNotes;
    }

    /**
     * Set the Justification for statements conveying a not_affected status to inform why the product is not affected by
     * the vulnerability
     */
    public void setJustification(Justification justification) {
        this.justification = justification;
    }

    /**
     * Set the free form text containing a description of why the vulnerability cannot be exploited
     */
    public void setImpactStatement(String impactStatement) {
        this.impactStatement = impactStatement;
    }

    /**
     * Set the statement that SHOULD describe actions to remediate or mitigate the vulnerability for statements with
     * "affected" status
     * <p>
     * Also sets the action_statement_timestamp field to now
     * </p>
     * @param actionStatement the action statement
     */
    public void setActionStatement(String actionStatement) {
        this.actionStatement = actionStatement;
        this.actionStatementTimestamp = OffsetDateTime.now();
    }

    @JsonGetter("timestamp")
    String serializeTimestamp() {
        if (null == this.timestamp) return null;
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(this.timestamp);
    }

    @JsonGetter("last_updated")
    String serializeLastUpdated() {
        if (null == this.lastUpdated) return null;
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(this.lastUpdated);
    }

    @JsonGetter("action_statement_timestamp")
    String serializeActionStatementTimestamp() {
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

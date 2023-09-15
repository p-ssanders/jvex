package dev.samsanders.openvex;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URI;
import java.util.Objects;

/**
 * The "abstract" type shared by Product and its subcomponents field
 */
@JsonInclude(Include.NON_NULL)
public sealed class Component permits Product {
    /**
     * Optional IRI identifying the component to make it externally referenceable.
     */
    @JsonProperty("@id")
    protected URI id;

    /**
     * A map of software identifiers where the key is the type and the value the
     * identifier.
     */
    private Identifiers identifiers;

    /**
     * Map of cryptographic hashes of the component.
     */
    private Hashes hashes;

    public URI getId() {
        return id;
    }

    public Identifiers getIdentifiers() {
        return identifiers;
    }

    public void setIdentifiers(Identifiers identifiers) {
        this.identifiers = identifiers;
    }

    public Hashes getHashes() {
        return hashes;
    }

    public void setHashes(Hashes hashes) {
        this.hashes = hashes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Component component = (Component) o;
        return Objects.equals(getId(), component.getId()) && Objects.equals(getIdentifiers(), component.getIdentifiers()) && Objects.equals(getHashes(), component.getHashes());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getId(), getIdentifiers(), getHashes());
    }

    @Override
    public String toString() {
        return "Component{" +
                "id=" + id +
                ", identifiers=" + identifiers +
                ", hashes=" + hashes +
                '}';
    }
}

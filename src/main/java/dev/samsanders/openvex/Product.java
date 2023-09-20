package dev.samsanders.openvex;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URI;
import java.util.Collection;
import java.util.Objects;

/**
 * Data structure to represent a piece of software
 */
@JsonInclude(Include.NON_NULL)
public final class Product extends Component {

    /**
     * List of component structs describing the subcomponents subject of the VEX
     * statement.
     */
    @JsonProperty("subcomponents")
    private Collection<Component> subcomponents;

    @JsonCreator
    public Product(@JsonProperty("@id") URI id) {
        this.id = id;
    }

    public Collection<Component> getSubcomponents() {
        return subcomponents;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        Product product = (Product) o;
        return Objects.equals(subcomponents, product.subcomponents);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), subcomponents);
    }

    @Override
    public String toString() {
        return "Product{" +
                "subcomponents=" + subcomponents +
                ", id=" + id +
                "} " + super.toString();
    }

}

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
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Objects.hash(subcomponents);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (!(obj instanceof Product))
            return false;
        Product other = (Product) obj;
        return Objects.equals(subcomponents, other.subcomponents);
    }

    @Override
    public String toString() {
        return "Product [subcomponents=" + subcomponents + "]";
    }

}

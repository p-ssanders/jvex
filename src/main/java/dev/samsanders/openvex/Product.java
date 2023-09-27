package dev.samsanders.openvex;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
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
    private Collection<Component> subcomponents;

    @JsonCreator
    public Product(@JsonProperty("@id") URI id) {
        this.id = id;
    }

    public Collection<Component> getSubcomponents() {
        if(null == this.subcomponents)
            this.subcomponents = new ArrayList<>();

        return subcomponents;
    }

    @JsonGetter("subcomponents")
    Collection<Component> serializeSubcomponents() {
        if(null != this.subcomponents && this.subcomponents.isEmpty())
            return null;

        return this.subcomponents;
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

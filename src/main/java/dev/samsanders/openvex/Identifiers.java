package dev.samsanders.openvex;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.packageurl.PackageURL;

import java.util.Objects;

/**
 * Software identifiers of a Component
 * Currently only supports purl
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class Identifiers {

    @JsonProperty("purl")
    private final PackageURL packageURL;

    @JsonCreator
    public Identifiers(@JsonProperty("purl") PackageURL packageURL) {
        this.packageURL = packageURL;
    }

    public PackageURL getPackageURL() {
        return packageURL;
    }

    @JsonGetter("purl")
    String serializePackageURL() {
        return packageURL.canonicalize();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Identifiers that = (Identifiers) o;
        return Objects.equals(packageURL, that.packageURL);
    }

    @Override
    public int hashCode() {
        return Objects.hash(packageURL);
    }

    @Override
    public String toString() {
        return "Identifiers{" +
                "packageURL=" + packageURL +
                '}';
    }
}

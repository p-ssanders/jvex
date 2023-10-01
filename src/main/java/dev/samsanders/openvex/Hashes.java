package dev.samsanders.openvex;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Data structure used to represent a map of cryptographic hashes of the component
 */
@JsonInclude(Include.NON_NULL)
public final class Hashes {

    @JsonProperty("md5")
    private String md5;
    @JsonProperty("sha1")
    private String sha1;
    @JsonProperty("sha-256")
    private String sha256;
    @JsonProperty("sha-384")
    private String sha384;
    @JsonProperty("sha-512")
    private String sha512;
    @JsonProperty("sha3-224")
    private String sha3224;
    @JsonProperty("sha3-256")
    private String sha3256;
    @JsonProperty("sha3-384")
    private String sha3384;
    @JsonProperty("sha3-512")
    private String sha3512;
    @JsonProperty("blake2s-256")
    private String blake2s256;
    @JsonProperty("blake2b-256")
    private String blake2b256;
    @JsonProperty("blake2b-512")
    private String blake2b512;

    @JsonCreator
    Hashes(
            @JsonProperty("md5") String md5,
            @JsonProperty("sha1") String sha1,
            @JsonProperty("sha-256") String sha256,
            @JsonProperty("sha-384") String sha384,
            @JsonProperty("sha-512") String sha512,
            @JsonProperty("sha3-224") String sha3224,
            @JsonProperty("sha3-256") String sha3256,
            @JsonProperty("sha3-384") String sha3384,
            @JsonProperty("sha3-512") String sha3512,
            @JsonProperty("blake2s-256") String blake2s256,
            @JsonProperty("blake2b-256") String blake2b256,
            @JsonProperty("blake2b-512") String blake2b512) {
        this.md5 = md5;
        this.sha1 = sha1;
        this.sha256 = sha256;
        this.sha384 = sha384;
        this.sha512 = sha512;
        this.sha3224 = sha3224;
        this.sha3256 = sha3256;
        this.sha3384 = sha3384;
        this.sha3512 = sha3512;
        this.blake2s256 = blake2s256;
        this.blake2b256 = blake2b256;
        this.blake2b512 = blake2b512;
    }

    public Hashes() {
    }

    public String getMd5() {
        return md5;
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }

    public String getSha1() {
        return sha1;
    }

    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    public String getSha384() {
        return sha384;
    }

    public void setSha384(String sha384) {
        this.sha384 = sha384;
    }

    public String getSha512() {
        return sha512;
    }

    public void setSha512(String sha512) {
        this.sha512 = sha512;
    }

    public String getSha3224() {
        return sha3224;
    }

    public void setSha3224(String sha3224) {
        this.sha3224 = sha3224;
    }

    public String getSha3256() {
        return sha3256;
    }

    public void setSha3256(String sha3256) {
        this.sha3256 = sha3256;
    }

    public String getSha3384() {
        return sha3384;
    }

    public void setSha3384(String sha3384) {
        this.sha3384 = sha3384;
    }

    public String getSha3512() {
        return sha3512;
    }

    public void setSha3512(String sha3512) {
        this.sha3512 = sha3512;
    }

    public String getBlake2s256() {
        return blake2s256;
    }

    public void setBlake2s256(String blake2s256) {
        this.blake2s256 = blake2s256;
    }

    public String getBlake2b256() {
        return blake2b256;
    }

    public void setBlake2b256(String blake2b256) {
        this.blake2b256 = blake2b256;
    }

    public String getBlake2b512() {
        return blake2b512;
    }

    public void setBlake2b512(String blake2b512) {
        this.blake2b512 = blake2b512;
    }

    Map<String, String> asMap() {
        HashMap<String, String> map = new HashMap<>();
        if(null != this.md5)
            map.put("md5", this.md5);
        if(null != this.sha1)
            map.put("sha1", this.sha1);
        if(null != this.sha256)
            map.put("sha-256", this.sha256);
        if(null != this.sha384)
            map.put("sha-384", this.sha384);
        if(null != this.sha512)
            map.put("sha-512", this.sha512);
        if(null != this.sha3224)
            map.put("sha3-224", this.sha3224);
        if(null != this.sha3256)
            map.put("sha3-256", this.sha3256);
        if(null != this.sha3384)
            map.put("sha3-384", this.sha3384);
        if(null != this.sha3512)
            map.put("sha3-512", this.sha3512);
        if(null != this.blake2s256)
            map.put("blake2s-256", this.blake2s256);
        if(null != this.blake2b256)
            map.put("blake2b-256", this.blake2b256);
        if(null != this.blake2b512)
            map.put("blake2b-512", this.blake2b512);
        return map;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Hashes hashes = (Hashes) o;
        return Objects.equals(getMd5(), hashes.getMd5()) && Objects.equals(getSha1(), hashes.getSha1()) && Objects.equals(getSha256(), hashes.getSha256()) && Objects.equals(getSha384(), hashes.getSha384()) && Objects.equals(getSha512(), hashes.getSha512()) && Objects.equals(getSha3224(), hashes.getSha3224()) && Objects.equals(getSha3256(), hashes.getSha3256()) && Objects.equals(getSha3384(), hashes.getSha3384()) && Objects.equals(getSha3512(), hashes.getSha3512()) && Objects.equals(getBlake2s256(), hashes.getBlake2s256()) && Objects.equals(getBlake2b256(), hashes.getBlake2b256()) && Objects.equals(getBlake2b512(), hashes.getBlake2b512());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getMd5(), getSha1(), getSha256(), getSha384(), getSha512(), getSha3224(), getSha3256(), getSha3384(), getSha3512(), getBlake2s256(), getBlake2b256(), getBlake2b512());
    }

    @Override
    public String toString() {
        return "Hashes{" +
                "md5='" + md5 + '\'' +
                ", sha1='" + sha1 + '\'' +
                ", sha256='" + sha256 + '\'' +
                ", sha384='" + sha384 + '\'' +
                ", sha512='" + sha512 + '\'' +
                ", sha3224='" + sha3224 + '\'' +
                ", sha3256='" + sha3256 + '\'' +
                ", sha3384='" + sha3384 + '\'' +
                ", sha3512='" + sha3512 + '\'' +
                ", blake2s256='" + blake2s256 + '\'' +
                ", blake2b256='" + blake2b256 + '\'' +
                ", blake2b512='" + blake2b512 + '\'' +
                '}';
    }
}

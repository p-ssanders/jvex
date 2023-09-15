package dev.samsanders.openvex;

/**
 * The known relationship a vulnerability has to a software product
 */
public enum Status {
    /**
     * No remediation is required regarding this vulnerability.
     */
    not_affected,

    /**
     * Actions are recommended to remediate or address this vulnerability.
     */
    affected,

    /**
     * These product versions contain a fix for the vulnerability.
     */
    fixed,

    /**
     * It is not yet known whether these product versions are affected by the
     * vulnerability.
     */
    under_investigation
}

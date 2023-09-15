package dev.samsanders.openvex;

/**
 * Consumers of a not_affected software product can know why the vulnerability is not affected by reading the
 * justification label associated with the VEX statement
 */
public enum Justification {
    /**
     * The product is not affected by the vulnerability because the component is not
     * included.
     */
    component_not_present,

    /**
     * The vulnerable component is included in artifact, but the vulnerable code is
     * not present.
     */
    vulnerable_code_not_present,

    /**
     * The vulnerable code (likely in subcomponents) can not be executed as it is
     * used by the product.
     */
    vulnerable_code_not_in_execute_path,

    /**
     * The vulnerable code cannot be controlled by an attacker to exploit the
     * vulnerability.
     */
    vulnerable_code_cannot_be_controlled_by_adversary,

    /**
     * The product includes built-in protections or features that prevent
     * exploitation of the vulnerability.
     */
    inline_mitigations_already_exist
}

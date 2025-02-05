#ifndef VERIFIER_HPP
#define VERIFIER_HPP

#ifdef __cplusplus
extern "C" {
#endif

// Error codes returned by the functions
#define VERIFIER_VALID_PROOF        0x0
#define VERIFIER_INVALID_PROOF      0x1
#define VERIFIER_ERROR              0x2

/**
 * Verifies a Groth16 proof.
 *
 * @param proof            Null-terminated JSON string of the proof.
 * @param wtns_binary      Raw witness binary data.
 * @param wtns_size        Size of the witness binary data.
 * @param inputs_json      Null-terminated JSON string of public inputs.
 * @param verification_key Null-terminated JSON string of the verification key.
 * @param error_msg        Buffer to store the error message (if any).
 * @param error_msg_maxsize Maximum size of the error message buffer.
 *
 * @return error code:
 *         VERIFIER_VALID_PROOF   - in case of valid proof.
 *         VERIFIER_INVALID_PROOF - in case of invalid proof.
 *         VERIFIER_ERROR         - in case of an error.
 */
int groth16_verify(
    const char *proof,
    const unsigned char *wtns_binary,  //  Updated to accept witness binary
    size_t wtns_size,                  //  Added witness size parameter
    const char *inputs_json,            //  Added JSON public inputs
    const char *verification_key,
    char *error_msg,
    unsigned long error_msg_maxsize);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
namespace rapidsnark {
#endif

    // Struct to return verification results in C-compatible format
    struct VerifyResult {
        int error_code;
        char *message;  // Pointer to error message (must be freed)
    };

    /**
     * Verifies a Groth16 proof.
     *
     * @param proof            Null-terminated JSON string of the proof.
     * @param wtns_binary      Raw witness binary data.
     * @param wtns_size        Size of the witness binary data.
     * @param inputs_json      Null-terminated JSON string of public inputs.
     * @param verification_key Null-terminated JSON string of the verification key.
     *
     * @return A VerifyResult struct containing the verification status and a dynamically allocated message.
     *         The caller (Rust) must call `free_verify_result` to release the allocated memory.
     */
    struct VerifyResult verify_proof(
        const char *proof,
        // const unsigned char *wtns_binary,  //  Updated to accept witness binary
        // size_t wtns_size,                  //  Added witness size parameter
        const char *inputs_json,            //  Added JSON public inputs
        const char *verification_key);

    /**
     * Frees the dynamically allocated message in VerifyResult.
     *
     * @param result VerifyResult struct containing the message to free.
     */
    void free_verify_result(struct VerifyResult result);

#ifdef __cplusplus
} // namespace rapidsnark
#endif

#ifdef __cplusplus
}
#endif

#endif // VERIFIER_HPP

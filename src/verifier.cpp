#include <string>
#include <stdexcept>
#include <alt_bn128.hpp>
#include <nlohmann/json.hpp>

#include "verifier.h"
#include "groth16.hpp"
#include "fr.hpp"

using json = nlohmann::json;

static Groth16::Proof<AltBn128::Engine>

parse_proof(const char *proof_str)
{
    //printf("entering parse proof\n");
    Groth16::Proof<AltBn128::Engine> proof(AltBn128::Engine::engine);

    try {
        json proof_json = json::parse(proof_str);

        std::string protocol = proof_json["protocol"].template get<std::string>();

        if (protocol != "groth16") {
            throw std::invalid_argument("invalid proof data");
        }

        proof.fromJson(proof_json);

    } catch(...) {
        throw std::invalid_argument("invalid proof data") ;
    }

    return proof;
}

static std::vector<AltBn128::FrElement>
parse_inputs(const char *inputs_str)
{    //printf("entering parse inputs\n");
    std::vector<AltBn128::FrElement> inputs;

    try {
        json inputs_json = json::parse(inputs_str);
        

        auto inputs_str_vec = inputs_json.template get<std::vector<std::string>>();
        //printf("inputs_str_vec object created\n");
        if (inputs_str_vec.empty()) {
            printf("inputs_str_vec is empty\n");
            throw std::invalid_argument("invalid inputs data");
        }
        //printf("inputs_str_vec is not empty\n");
        inputs.reserve(inputs_str_vec.size());
        //printf("inputs_str_vec size: %zu\n", inputs_str_vec.size());
        
        int i=0;
        for (const auto& elem: inputs_str_vec) {
           
            AltBn128::FrElement aux;
            
            //printf("entering aux from string\n");
            AltBn128::Fr.fromString(aux, elem);
            //printf("exiting aux from string\n");    
            inputs.push_back(aux);
            //printf("aux pushed\n");
        }
        //printf("Parsed inputs successful -- inputs size: %zu\n", inputs.size());

    } catch(...) {
        //printf("invalid inputs exception thrown\n");
        throw std::invalid_argument("invalid inputs data") ;
    }

    return inputs;
}

static Groth16::VerificationKey<AltBn128::Engine>
parse_key(const char *key_str)
{   //printf("entering parse key\n");
    Groth16::VerificationKey<AltBn128::Engine> key(AltBn128::Engine::engine);

    try {
        json key_json = json::parse(key_str);

        auto protocol = key_json["protocol"].template get<std::string>();
        auto curve    = key_json["curve"].template get<std::string>();
        auto nPublic  = key_json["nPublic"].template get<int64_t>();

        if (protocol != "groth16" || curve != "bn128") {
            throw std::invalid_argument("invalid verification key data");
        }

        key.fromJson(key_json);

        if (key.IC.empty()) {
            throw std::invalid_argument("invalid verification key data");
        }

    } catch(...) {
        throw std::invalid_argument("invalid verification key data");
    }

    return key;
}

int
groth16_verify(const char    *proof,
               const char    *inputs,
               const char    *verification_key,
               char          *error_msg,
               unsigned long  error_msg_maxsize)
{
    int init_val = Fr_reInit();
    //printf("Fr_init value: %d\n", init_val);
    try {
        Groth16::Verifier<AltBn128::Engine> verifier;
        auto proof_value = parse_proof(proof);
        //printf("parse_proof_success\n");
        auto key_value = parse_key(verification_key);
        //printf("parse_key_success\n");
        auto inputs_value = parse_inputs(inputs);
        //printf("parse_inputs_success\n");
        
        bool valid = verifier.verify(proof_value, inputs_value, key_value);

        return valid ? VERIFIER_VALID_PROOF : VERIFIER_INVALID_PROOF;

    } catch (std::exception& e) {

        if (error_msg) {
            strncpy(error_msg, e.what(), error_msg_maxsize);
        }
        return VERIFIER_ERROR;

    } catch (std::exception *e) {

        if (error_msg) {
            strncpy(error_msg, e->what(), error_msg_maxsize);
        }
        delete e;
        return VERIFIER_ERROR;

    } catch (...) {
        if (error_msg) {
            strncpy(error_msg, "unknown error", error_msg_maxsize);
        }
        return VERIFIER_ERROR;
    }

    return VERIFIER_INVALID_PROOF;
}


int groth16_verify_verita(
    const char *proof,
    std::vector<AltBn128::FrElement> &witnessData,  //  Directly use deserialized witness data
    const char *verification_key,
    char *error_msg,
    unsigned long error_msg_maxsize)
{
    try {
        Groth16::Verifier<AltBn128::Engine> verifier;
        auto proof_value = parse_proof(proof);
        //printf("parse_proof_success\n");
        auto key_value = parse_key(verification_key);
        //printf("parse_key_success\n");

        bool valid = verifier.verify(proof_value, witnessData, key_value);

        return valid ? VERIFIER_VALID_PROOF : VERIFIER_INVALID_PROOF;

    } catch (const std::exception &e) {
        if (error_msg) {
            strncpy(error_msg, e.what(), error_msg_maxsize);
        }
        return VERIFIER_ERROR;

    } catch (...) {
        if (error_msg) {
            strncpy(error_msg, "unknown error", error_msg_maxsize);
        }
        return VERIFIER_ERROR;
    }
}


namespace rapidsnark {
    // Debug function to print input strings
    void debug_print(const char* label, const char* value) {
        std::cerr << "[DEBUG] " << label << ": " << (value ? value : "NULL") << std::endl;
    }
    // Library function to verify a Groth16 proof (FFI-Compatible)
    // Library function to verify a Groth16 proof (FFI-Compatible)
    VerifyResult verify_proof(
    const char* proof, 
    // const unsigned char* wtns_binary,  //  Witness binary data
    // size_t wtns_size,                  //  Witness binary size
    const char* inputs_json,            //  JSON string of public inputs
    const char* key) {

        char errorMessage[256] = {0};  // Buffer for error messages
        //printf("entering C++ verify_proof\n");

        // // Debug: Print inputs before calling `groth16_verify_verita`
        // std::cerr << "[DEBUG] Proof length: " << (proof ? strlen(proof) : 0) << std::endl;
        // std::cerr << "[DEBUG] Witness Binary Size: " << wtns_size << " bytes" << std::endl;
        // std::cerr << "[DEBUG] Public Inputs JSON length: " << (inputs_json ? strlen(inputs_json) : 0) << std::endl;
        // std::cerr << "[DEBUG] Verification Key length: " << (key ? strlen(key) : 0) << std::endl;

        //  Check for null inputs
        if (!proof || !inputs_json || !key) {
            std::cerr << "[ERROR] NULL pointer received in verify_proof!" << std::endl;
            return {VERIFIER_ERROR, strdup("Null pointer received")}; // Return safe error message
        }
        
        int error = groth16_verify(proof, inputs_json, key, errorMessage, sizeof(errorMessage));

        
        //  Debug: Print result
        //std::cerr << "[DEBUG] groth16_verify returned error_code: " << error << std::endl;

        //  Determine the appropriate message
        const char* message;
        if (error == VERIFIER_VALID_PROOF) {
            message = "Valid proof";
        } else if (error == VERIFIER_INVALID_PROOF) {
            message = "Invalid proof";
        } else {
            message = errorMessage;  // Use the error message from `groth16_verify_verita`
        }

        // Debug: Print final message
        //std::cerr << "[DEBUG] Verification message: " << message << std::endl;

        // Allocate memory for the message (Rust must free this)
        char* message_alloc = static_cast<char*>(malloc(strlen(message) + 1));
        if (message_alloc) {
            strcpy(message_alloc, message);
        } else {
            std::cerr << "[ERROR] Failed to allocate memory for message" << std::endl;
        }

        return {error, message_alloc}; // Return the result struct
    }



    // Function to free the dynamically allocated message
    void free_verify_result(VerifyResult result) {
        if (result.message) {
            //std::cerr << "[DEBUG] Freeing message: " << result.message << std::endl;
            free(result.message);
        }
    }

} // namespace rapidsnark
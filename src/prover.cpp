#include <gmp.h>
#include <string>
#include <cstring>
#include <stdexcept>
#include <alt_bn128.hpp>
#include <nlohmann/json.hpp>
#include "prover.h"
#include "groth16.hpp"
#include "zkey_utils.hpp"
#include "wtns_utils.hpp"
#include "binfile_utils.hpp"
#include "fileloader.hpp"

using json = nlohmann::json;

struct Groth16ProofResult {
    std::string proof;         // The generated proof in JSON format
    std::string publicInputs;  // The public inputs in JSON format
    std::string errorMsg;      // Error message (empty if success)
    bool success;              // Whether proof generation succeeded
};


class ShortBufferException : public std::invalid_argument
{
public:
    explicit ShortBufferException(const std::string &msg)
        : std::invalid_argument(msg) {}
};

class InvalidWitnessLengthException : public std::invalid_argument
{
public:
    explicit InvalidWitnessLengthException(const std::string &msg)
        : std::invalid_argument(msg) {}
};

static void
CopyError(
    char                 *error_msg,
    unsigned long long    error_msg_maxsize,
    const std::exception &e)
{
    if (error_msg) {
        strncpy(error_msg, e.what(), error_msg_maxsize);
    }
}

static void
CopyError(
    char               *error_msg,
    unsigned long long  error_msg_maxsize,
    const char         *str)
{
    if (error_msg) {
        strncpy(error_msg, str, error_msg_maxsize);
    }
}

static unsigned long long
ProofBufferMinSize()
{
    return 810;
}

static unsigned long long
PublicBufferMinSize(unsigned long long count)
{
    return count * 82 + 4;
}

static bool
PrimeIsValid(mpz_srcptr prime)
{
    mpz_t altBbn128r;

    mpz_init(altBbn128r);
    mpz_set_str(altBbn128r, "21888242871839275222246405745257275088548364400416034343698204186575808495617", 10);

    const bool is_valid = (mpz_cmp(prime, altBbn128r) == 0);

    mpz_clear(altBbn128r);

    return is_valid;
}

static std::string
BuildPublicString(AltBn128::FrElement *wtnsData, uint32_t nPublic)
{
    json jsonPublic;
    AltBn128::FrElement aux;
    for (u_int32_t i=1; i<= nPublic; i++) {
        AltBn128::Fr.toMontgomery(aux, wtnsData[i]);
        jsonPublic.push_back(AltBn128::Fr.toString(aux));
    }

    return jsonPublic.dump();
}

static void
CheckAndUpdateBufferSizes(
    unsigned long long   proofCalcSize,
    unsigned long long  *proofSize,
    unsigned long long   publicCalcSize,
    unsigned long long  *publicSize,
    const std::string   &type)
{
    if (*proofSize < proofCalcSize || *publicSize < publicCalcSize) {

        *proofSize  = proofCalcSize;
        *publicSize = publicCalcSize;

        if (*proofSize < proofCalcSize) {
            throw ShortBufferException("Proof buffer is too short. " + type + " size: "
                                       + std::to_string(proofCalcSize) +
                                       ", actual size: "
                                       + std::to_string(*proofSize));
        } else {
            throw ShortBufferException("Public buffer is too short. " + type + " size: "
                                       + std::to_string(proofCalcSize) +
                                       ", actual size: "
                                       + std::to_string(*proofSize));
       }
    }
}

class Groth16Prover
{
    BinFileUtils::BinFile zkey;
    std::unique_ptr<ZKeyUtils::Header> zkeyHeader;
    std::unique_ptr<Groth16::Prover<AltBn128::Engine>> prover;

public:
    Groth16Prover(const void         *zkey_buffer,
                  unsigned long long  zkey_size)

        : zkey(zkey_buffer, zkey_size, "zkey", 1),
          zkeyHeader(ZKeyUtils::loadHeader(&zkey))
    {
        if (!PrimeIsValid(zkeyHeader->rPrime)) {
            throw std::invalid_argument("zkey curve not supported");
        }

        prover = Groth16::makeProver<AltBn128::Engine>(
            zkeyHeader->nVars,
            zkeyHeader->nPublic,
            zkeyHeader->domainSize,
            zkeyHeader->nCoefs,
            zkeyHeader->vk_alpha1,
            zkeyHeader->vk_beta1,
            zkeyHeader->vk_beta2,
            zkeyHeader->vk_delta1,
            zkeyHeader->vk_delta2,
            zkey.getSectionData(4),    // Coefs
            zkey.getSectionData(5),    // pointsA
            zkey.getSectionData(6),    // pointsB1
            zkey.getSectionData(7),    // pointsB2
            zkey.getSectionData(8),    // pointsC
            zkey.getSectionData(9)     // pointsH1
        );
    }

    void prove(const void         *wtns_buffer,
               unsigned long long  wtns_size,
               std::string        &stringProof,
               std::string        &stringPublic)
    {
        BinFileUtils::BinFile wtns(wtns_buffer, wtns_size, "wtns", 2);
        auto wtnsHeader = WtnsUtils::loadHeader(&wtns);

        if (zkeyHeader->nVars != wtnsHeader->nVars) {
            throw InvalidWitnessLengthException("Invalid witness length. Circuit: "
                                        + std::to_string(zkeyHeader->nVars)
                                        + ", witness: "
                                        + std::to_string(wtnsHeader->nVars));
        }

        if (!PrimeIsValid(wtnsHeader->prime)) {
            throw std::invalid_argument("different wtns curve");
        }

        AltBn128::FrElement *wtnsData = (AltBn128::FrElement *)wtns.getSectionData(2);

        auto proof = prover->prove(wtnsData);

        stringProof = proof->toJson().dump();
        stringPublic = BuildPublicString(wtnsData, zkeyHeader->nPublic);
    }

    unsigned long long proofBufferMinSize() const
    {
        return ProofBufferMinSize();
    }

    unsigned long long publicBufferMinSize() const
    {
        return PublicBufferMinSize(zkeyHeader->nPublic);
    }
};

int
groth16_public_size_for_zkey_buf(
    const void          *zkey_buffer,
    unsigned long long   zkey_size,
    unsigned long long  *public_size,
    char                *error_msg,
    unsigned long long   error_msg_maxsize)
{
    try {
        BinFileUtils::BinFile zkey(zkey_buffer, zkey_size, "zkey", 1);
        auto zkeyHeader = ZKeyUtils::loadHeader(&zkey);

        *public_size = PublicBufferMinSize(zkeyHeader->nPublic);

    } catch (std::exception& e) {
        CopyError(error_msg, error_msg_maxsize, e);
        return PROVER_ERROR;

    } catch (...) {
        CopyError(error_msg, error_msg_maxsize, "unknown error");
        return PROVER_ERROR;
    }

    return PROVER_OK;
}

int
groth16_public_size_for_zkey_file(
    const char          *zkey_fname,
    unsigned long long  *public_size,
    char                *error_msg,
    unsigned long long   error_msg_maxsize)
{
    try {
        auto zkey = BinFileUtils::openExisting(zkey_fname, "zkey", 1);
        auto zkeyHeader = ZKeyUtils::loadHeader(zkey.get());

        *public_size = PublicBufferMinSize(zkeyHeader->nPublic);

    } catch (std::exception& e) {
        CopyError(error_msg, error_msg_maxsize, e);
        return PROVER_ERROR;

    } catch (...) {
        CopyError(error_msg, error_msg_maxsize, "unknown error");
        return PROVER_ERROR;
    }

    return PROVER_OK;
}

void
groth16_proof_size(
    unsigned long long *proof_size)
{
    *proof_size = ProofBufferMinSize();
}

int
groth16_prover_create(
    void                **prover_object,
    const void          *zkey_buffer,
    unsigned long long   zkey_size,
    char                *error_msg,
    unsigned long long   error_msg_maxsize)
{
    try {
        if (prover_object == NULL) {
            throw std::invalid_argument("Null prover object");
        }

        if (zkey_buffer == NULL) {
            throw std::invalid_argument("Null zkey buffer");
        }

        Groth16Prover *prover = new Groth16Prover(zkey_buffer, zkey_size);

        *prover_object = prover;

    } catch (std::exception& e) {
        CopyError(error_msg, error_msg_maxsize, e);
        return PROVER_ERROR;

    } catch (std::exception *e) {
        CopyError(error_msg, error_msg_maxsize, *e);
        delete e;
        return PROVER_ERROR;

    } catch (...) {
        CopyError(error_msg, error_msg_maxsize, "unknown error");
        return PROVER_ERROR;
    }

    return PROVER_OK;
}

int
groth16_prover_create_zkey_file(
    void                **prover_object,
    const char          *zkey_file_path,
    char                *error_msg,
    unsigned long long   error_msg_maxsize)
{
    BinFileUtils::FileLoader fileLoader;

    try {
        fileLoader.load(zkey_file_path);

    } catch (std::exception& e) {
        CopyError(error_msg, error_msg_maxsize, e);
        return PROVER_ERROR;
    }

    return groth16_prover_create(
                prover_object,
                fileLoader.dataBuffer(),
                fileLoader.dataSize(),
                error_msg,
                error_msg_maxsize);
}

int
groth16_prover_prove(
    void                *prover_object,
    const void          *wtns_buffer,
    unsigned long long   wtns_size,
    char                *proof_buffer,
    unsigned long long  *proof_size,
    char                *public_buffer,
    unsigned long long  *public_size,
    char                *error_msg,
    unsigned long long   error_msg_maxsize)
{
    try {
        if (prover_object == NULL) {
            throw std::invalid_argument("Null prover object");
        }

        if (wtns_buffer == NULL) {
            throw std::invalid_argument("Null witness buffer");
        }

        if (proof_buffer == NULL) {
            throw std::invalid_argument("Null proof buffer");
        }

        if (proof_size == NULL) {
            throw std::invalid_argument("Null proof size");
        }

        if (public_buffer == NULL) {
            throw std::invalid_argument("Null public buffer");
        }

        if (public_size == NULL) {
            throw std::invalid_argument("Null public size");
        }

        Groth16Prover *prover = static_cast<Groth16Prover*>(prover_object);

        CheckAndUpdateBufferSizes(prover->proofBufferMinSize(), proof_size,
                                  prover->publicBufferMinSize(), public_size,
                                  "Minimum");

        std::string stringProof;
        std::string stringPublic;

        prover->prove(wtns_buffer, wtns_size, stringProof, stringPublic);

        CheckAndUpdateBufferSizes(stringProof.length(), proof_size,
                                  stringPublic.length(), public_size,
                                  "Required");

        std::strncpy(proof_buffer, stringProof.c_str(), *proof_size);
        std::strncpy(public_buffer, stringPublic.c_str(), *public_size);

    } catch(InvalidWitnessLengthException& e) {
        CopyError(error_msg, error_msg_maxsize, e);
        return PROVER_INVALID_WITNESS_LENGTH;

    } catch(ShortBufferException& e) {
        CopyError(error_msg, error_msg_maxsize, e);
        return PROVER_ERROR_SHORT_BUFFER;

    } catch (std::exception& e) {
        CopyError(error_msg, error_msg_maxsize, e);
        return PROVER_ERROR;

    } catch (std::exception *e) {
        CopyError(error_msg, error_msg_maxsize, *e);
        delete e;
        return PROVER_ERROR;

    } catch (...) {
        CopyError(error_msg, error_msg_maxsize, "unknown error");
        return PROVER_ERROR;
    }

    return PROVER_OK;
}

void
groth16_prover_destroy(void *prover_object)
{
    if (prover_object != NULL) {
        Groth16Prover *prover = static_cast<Groth16Prover*>(prover_object);

        delete prover;
    }
}

int
groth16_prover(
    const void          *zkey_buffer,
    unsigned long long   zkey_size,
    const void          *wtns_buffer,
    unsigned long long   wtns_size,
    char                *proof_buffer,
    unsigned long long  *proof_size,
    char                *public_buffer,
    unsigned long long  *public_size,
    char                *error_msg,
    unsigned long long   error_msg_maxsize)
{
    void *prover = NULL;

    int error = groth16_prover_create(
                    &prover,
                    zkey_buffer,
                    zkey_size,
                    error_msg,
                    error_msg_maxsize);

    if (error != PROVER_OK) {
        return error;
    }

    error = groth16_prover_prove(
                    prover,
                    wtns_buffer,
                    wtns_size,
                    proof_buffer,
                    proof_size,
                    public_buffer,
                    public_size,
                    error_msg,
                    error_msg_maxsize);

    groth16_prover_destroy(prover);

    return error;
}

int
groth16_prover_zkey_file(
    const char          *zkey_file_path,
    const void          *wtns_buffer,
    unsigned long long   wtns_size,
    char                *proof_buffer,
    unsigned long long  *proof_size,
    char                *public_buffer,
    unsigned long long  *public_size,
    char                *error_msg,
    unsigned long long   error_msg_maxsize)
{
    BinFileUtils::FileLoader fileLoader;

    try {
        fileLoader.load(zkey_file_path);

    } catch (std::exception& e) {
        CopyError(error_msg, error_msg_maxsize, e);
        return PROVER_ERROR;
    }

    return groth16_prover(
            fileLoader.dataBuffer(),
            fileLoader.dataSize(),
            wtns_buffer,
            wtns_size,
            proof_buffer,
            proof_size,
            public_buffer,
            public_size,
            error_msg,
            error_msg_maxsize);
}

Groth16ProofResult generate_groth16_proof(
    const std::vector<char> &zkeyData,
    const std::vector<char> &wtnsData)
{
    Groth16ProofResult result;
    result.success = false;  // Default to failure until success is confirmed

    try {
        // Buffers for proof and public input
        std::vector<char> publicBuffer;
        std::vector<char> proofBuffer;
        unsigned long long publicSize = 0;
        unsigned long long proofSize = 0;
        char errorMsgBuffer[1024];

        // Get required public input buffer size
        int error = groth16_public_size_for_zkey_buf(
            zkeyData.data(),
            zkeyData.size(),
            &publicSize,
            errorMsgBuffer,
            sizeof(errorMsgBuffer));

        if (error != PROVER_OK) {
            result.errorMsg = errorMsgBuffer;
            return result;
        }
    
        groth16_proof_size(&proofSize);

        // Allocate buffers
        publicBuffer.resize(publicSize);
        proofBuffer.resize(proofSize);

        // Generate the proof
        error = groth16_prover(
            zkeyData.data(),
            zkeyData.size(),
            wtnsData.data(),
            wtnsData.size(),
            proofBuffer.data(),
            &proofSize,
            publicBuffer.data(),
            &publicSize,
            errorMsgBuffer,
            sizeof(errorMsgBuffer));

        if (error != PROVER_OK) {
            result.errorMsg = errorMsgBuffer;
            return result;
        }

        // Convert proof and public input buffers to strings
        result.proof = std::string(proofBuffer.data(), proofSize);
        result.publicInputs = std::string(publicBuffer.data(), publicSize);
        result.success = true;
    
    }catch (const std::exception &e) {
        result.errorMsg = e.what();
    }

    return result;
}

extern "C" {

Groth16ProofResultFFI generate_groth16_proof_ffi(
    const char *zkey_data, unsigned long long zkey_size,
    const char *wtns_data, unsigned long long wtns_size)
{
    Groth16ProofResultFFI result;

    try {
        // Convert raw buffers to std::vector<char>
        std::vector<char> zkeyVec(zkey_data, zkey_data + zkey_size);
        std::vector<char> wtnsVec(wtns_data, wtns_data + wtns_size);

        // Call the actual proof function
        Groth16ProofResult proofResult = generate_groth16_proof(zkeyVec, wtnsVec);

        if (!proofResult.success) {
            // Allocate and return the error message
            result.error_msg = strdup(proofResult.errorMsg.c_str());
            result.success = 0;
            return result;
        }

        // Allocate proof and public input buffers
        result.proof = strdup(proofResult.proof.c_str());
        result.public_inputs = strdup(proofResult.publicInputs.c_str());
        result.error_msg = nullptr;
        result.success = 1;

    } catch (const std::exception &e) {
        result.error_msg = strdup(e.what());
        result.success = 0;
    }

    return result;
}

// Free memory allocated by generate_groth16_proof_ffi
void free_groth16_proof_result(Groth16ProofResultFFI result)
{
    if (result.proof) free(result.proof);
    if (result.public_inputs) free(result.public_inputs);
    if (result.error_msg) free(result.error_msg);
}

}


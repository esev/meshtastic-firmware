#include "CryptoEngine.h"
// #include "NodeDB.h"
#include "architecture.h"
#include <type_traits>

#if !(MESHTASTIC_EXCLUDE_PKI)
#include "aes-ccm.h"
#include "meshUtils.h"
#include <Crypto.h>
#include <Curve25519.h>
#include <SHA256.h>
#endif

namespace
{
/**
 * Our per packet nonce.
 *
 * The same nonce generation logic is used for both Channel (AES-CTR) and PKI (AES-CCM/Curve25519) algorithms.
 * In both cases, the `set` or `setRandom` methods should be called to populate the nonce values. The individual
 * `aes_ctr` and `aes_ccm` fields are used to access the nonce byte values for each respective algorithm.
 *
 * The NONCE is constructed by concatenating:
 * a 32 bit packet number (stored in little endian order)
 * a 32 bit block counter (0 for Channel/AES-CTR encryption)
 * a 32 bit sending node number (stored in little endian order)
 */
static union {
    struct __attribute__((packed, aligned(4))) {
        uint32_t packetId;                      // Little endian
        CryptoEngine::extra_nonce_t extraNonce; // Interpreted as 4 bytes
        NodeNum fromNode;                       // Little endian

        static_assert(std::is_same<decltype(packetId), decltype(meshtastic_MeshPacket::id)>::value,
                      "packetId is expected to be the same type as MeshPacket::id");
        static_assert(std::is_same<decltype(fromNode), decltype(meshtastic_MeshPacket::from)>::value,
                      "fromNode is expected to be the same type as MeshPacket::from");
    } values; // Individual fields are populated by the `set` method below.

    /**
     * Set our nonce for a new packet.
     *
     * @param fromNode The MeshPacket `from` field.
     * @param packetId The MeshPacket `packet_id` field.
     * @param extraNonce Random 4 byte nonce (default = 0).
     */
    inline void set(NodeNum fromNode, uint32_t packetId, CryptoEngine::extra_nonce_t extraNonce = 0)
    {
        values.packetId = packetId;
        values.extraNonce = extraNonce;
        values.fromNode = fromNode;

        // Set the remaining memory in the nonce, after the `values`, to 0.
        static uint32_t &remainingNonce = *reinterpret_cast<uint32_t *>(&values + 1);
        remainingNonce = 0;
        static_assert(sizeof(values) + sizeof(remainingNonce) == sizeof(*this),
                      "expected remainingNonce to be the last 4 bytes of the nonce");
    }

    /**
     * Set our nonce for a new packet with a randomly generated extraNonce value.
     *
     * @param fromNode The MeshPacket `from` field.
     * @param packetId The MeshPacket `packet_id` field.
     */
    inline CryptoEngine::extra_nonce_t setRandom(NodeNum fromNode, uint32_t packetId)
    {
        CryptoEngine::extra_nonce_t extraNonce = random();
        LOG_INFO("Random nonce value: %d", extraNonce);
        set(fromNode, packetId, extraNonce);
        return extraNonce;
        static_assert(sizeof(extraNonce) >= sizeof(decltype(random())),
                      "sizeof(random()) output is less than sizeof(extra_nonce_t)");
    }

    uint8_t aes_ctr[16]; // Used by Channel (AES-CTR) to read the nonce value
    static_assert(sizeof(aes_ctr) >= sizeof(values), "AES-CTR nonce buffer too small for nonce values");
#if !(MESHTASTIC_EXCLUDE_PKI)
    const uint8_t aes_ccm[13]; // Used by PKI (AES-CCM/Curve25519) to read the nonce value
    static_assert(sizeof(aes_ccm) >= sizeof(values), "PKI nonce buffer too small for nonce values");
    static_assert(sizeof(aes_ccm) + kAESCCMLengthFieldSize == 15, "Nonce size + L must equal 15 per RFC 3610");
#endif
} nonce __attribute__((aligned(4))) = {0};
} // namespace

#if !(MESHTASTIC_EXCLUDE_PKI)
#if !(MESHTASTIC_EXCLUDE_PKI_KEYGEN)

/**
 * Create a public/private key pair with Curve25519.
 *
 * @param pubKey The destination for the public key.
 * @param privKey The destination for the private key.
 */
void CryptoEngine::generateKeyPair(uint8_t *pubKey, uint8_t *privKey)
{
    LOG_DEBUG("Generate Curve25519 keypair");
    Curve25519::dh1(public_key, private_key);
    memcpy(pubKey, public_key, sizeof(public_key));
    memcpy(privKey, private_key, sizeof(private_key));
}

/**
 * regenerate a public key with Curve25519.
 *
 * @param pubKey The destination for the public key.
 * @param privKey The source for the private key.
 */
bool CryptoEngine::regeneratePublicKey(uint8_t *pubKey, uint8_t *privKey)
{
    if (!memfll(privKey, 0, sizeof(private_key))) {
        Curve25519::eval(pubKey, privKey, 0);
        if (Curve25519::isWeakPoint(pubKey)) {
            LOG_ERROR("PKI key generation failed. Specified private key results in a weak");
            memset(pubKey, 0, 32);
            return false;
        }
        memcpy(private_key, privKey, sizeof(private_key));
        memcpy(public_key, pubKey, sizeof(public_key));
    } else {
        LOG_WARN("X25519 key generation failed due to blank private key");
        return false;
    }
    return true;
}
#endif
void CryptoEngine::clearKeys()
{
    memset(public_key, 0, sizeof(public_key));
    memset(private_key, 0, sizeof(private_key));
}

/**
 * Encrypt a packet's payload using a key generated with Curve25519 and SHA256
 * for a specific node.
 *
 * @param toNode The MeshPacket `to` field.
 * @param fromNode The MeshPacket `from` field.
 * @param remotePublic The remote node's Curve25519 public key.
 * @param packetId The MeshPacket `packet_id` field.
 * @param numBytes Number of bytes of plaintext in the bytes buffer.
 * @param bytes Buffer containing plaintext input.
 * @param bytesOut Output buffer to be populated with encrypted ciphertext.
 */
bool CryptoEngine::encryptCurve25519(NodeNum toNode, NodeNum fromNode, const meshtastic_UserLite_public_key_t remotePublic,
                                     uint32_t packetId, size_t numBytes, const uint8_t *bytes, uint8_t *bytesOut)
{
    if (remotePublic.size == 0) {
        LOG_DEBUG("Node %d or their public_key not found", toNode);
        return false;
    }
    if (!crypto->setDHPublicKey(remotePublic.bytes)) {
        return false;
    }

    // Calculate the shared secret with the destination node and encrypt
    crypto->hash(shared_key, 32);
    const extra_nonce_t extraNonce = nonce.setRandom(fromNode, packetId);
    printBytes("Attempt encrypt with nonce: ", nonce.aes_ccm, sizeof(nonce.aes_ccm));
    printBytes("Attempt encrypt with shared_key starting with: ", shared_key, 8);

    //                         |<---- kCurve25519Overhead --->|
    // bytesOut format:
    // +--- ~ ~ ~ ~ ~ ~ ~ ~ ---+-------------+----------------+
    // | ciphertext (numBytes) | authTag (8) | extraNonce (4) |
    // +--- ~ ~ ~ ~ ~ ~ ~ ~ ---+-------------+----------------+
    //
    // |<----- Populated by aes_ccm_ae ----->|<--- memcpy --->|
    uint8_t *authTag = bytesOut + numBytes;
    if (aes_ccm_ae(shared_key, 32, nonce.aes_ccm, kTagSizeM, bytes, numBytes, nullptr, 0, bytesOut, authTag) != 0)
        return false;

    // Append the random nonce value after the authTag. Must be done with memcpy as authTag
    // may not be 4 byte aligned.
    memcpy((uint8_t *)(authTag + kTagSizeM), &extraNonce, sizeof(extraNonce));
    return true;
}

/**
 * Decrypt a packet's payload using a key generated with Curve25519 and SHA256
 * for a specific node.
 *
 * @param fromNode The MeshPacket `from` field.
 * @param remotePublic The remote node's Curve25519 public key.
 * @param packetId The MeshPacket `packet_id` field.
 * @param numBytes Number of bytes of ciphertext in the bytes buffer.
 * @param bytes Buffer containing ciphertext input.
 * @param bytesOut Output buffer to be populated with decrypted plaintext.
 */
bool CryptoEngine::decryptCurve25519(NodeNum fromNode, const meshtastic_UserLite_public_key_t remotePublic, uint32_t packetId,
                                     size_t numBytes, const uint8_t *bytes, uint8_t *bytesOut)
{
    if (remotePublic.size == 0) {
        LOG_DEBUG("Node or its public key not found in database");
        return false;
    }
    // Calculate the shared secret with the sending node and decrypt
    if (!crypto->setDHPublicKey(remotePublic.bytes)) {
        return false;
    }
    crypto->hash(shared_key, 32);

    numBytes -= kCurve25519Overhead; // Overhead includes authTag(8) + extraNonce(4).
    const uint8_t *authTag = bytes + numBytes;

    extra_nonce_t extraNonce;
    memcpy(&extraNonce, authTag + kTagSizeM, sizeof(extraNonce));
    LOG_INFO("Random nonce value: %d", extraNonce);
    nonce.set(fromNode, packetId, extraNonce);
    printBytes("Attempt decrypt with nonce: ", nonce.aes_ccm, sizeof(nonce.aes_ccm));

    printBytes("Attempt decrypt with shared_key starting with: ", shared_key, 8);
    return aes_ccm_ad(shared_key, 32, nonce.aes_ccm, kTagSizeM, bytes, numBytes, nullptr, 0, authTag, bytesOut);
}

void CryptoEngine::setDHPrivateKey(uint8_t *_private_key)
{
    memcpy(private_key, _private_key, 32);
}

/**
 * Hash arbitrary data using SHA256.
 *
 * @param bytes
 * @param numBytes
 */
void CryptoEngine::hash(uint8_t *bytes, size_t numBytes)
{
    SHA256 hash;
    size_t posn;
    uint8_t size = numBytes;
    uint8_t inc = 16;
    hash.reset();
    for (posn = 0; posn < size; posn += inc) {
        size_t len = size - posn;
        if (len > inc)
            len = inc;
        hash.update(bytes + posn, len);
    }
    hash.finalize(bytes, 32);
}

void CryptoEngine::aesSetKey(const uint8_t *key_bytes, size_t key_len)
{
    if (aes) {
        delete aes;
        aes = nullptr;
    }
    if (key_len != 0) {
        aes = new AESSmall256();
        aes->setKey(key_bytes, key_len);
    }
}

void CryptoEngine::aesEncrypt(uint8_t *in, uint8_t *out)
{
    aes->encryptBlock(out, in);
}

bool CryptoEngine::setDHPublicKey(const uint8_t *pubKey)
{
    uint8_t local_priv[32];
    memcpy(shared_key, pubKey, 32);
    memcpy(local_priv, private_key, 32);
    // Calculate the shared secret with the specified node's public key and our private key
    // This includes an internal weak key check, which among other things looks for an all 0 public key and shared key.
    if (!Curve25519::dh2(shared_key, local_priv)) {
        LOG_WARN("Curve25519DH step 2 failed!");
        return false;
    }
    return true;
}

#endif
concurrency::Lock *cryptLock;

void CryptoEngine::setKey(const CryptoKey &k)
{
    LOG_DEBUG("Use AES%d key!", k.length * 8);
    key = k;
}

/**
 * Encrypt a packet
 *
 * @param bytes is updated in place
 */
void CryptoEngine::encryptPacket(NodeNum fromNode, uint32_t packetId, size_t numBytes, uint8_t *bytes)
{
    if (key.length > 0) {
        nonce.set(fromNode, packetId);
        if (numBytes <= MAX_BLOCKSIZE) {
            encryptAESCtr(key, nonce.aes_ctr, numBytes, bytes);
        } else {
            LOG_ERROR("Packet too large for crypto engine: %d. noop encryption!", numBytes);
        }
    }
}

void CryptoEngine::decrypt(NodeNum fromNode, uint32_t packetId, size_t numBytes, uint8_t *bytes)
{
    // For CTR, the implementation is the same
    encryptPacket(fromNode, packetId, numBytes, bytes);
}

// Generic implementation of AES-CTR encryption.
void CryptoEngine::encryptAESCtr(CryptoKey _key, uint8_t *_nonce, size_t numBytes, uint8_t *bytes)
{
    if (ctr) {
        delete ctr;
        ctr = nullptr;
    }
    if (_key.length == 16)
        ctr = new CTR<AES128>();
    else
        ctr = new CTR<AES256>();
    ctr->setKey(_key.bytes, _key.length);
    static uint8_t scratch[MAX_BLOCKSIZE];
    memcpy(scratch, bytes, numBytes);
    memset(scratch + numBytes, 0,
           sizeof(scratch) - numBytes); // Fill rest of buffer with zero (in case cypher looks at it)

    ctr->setIV(_nonce, 16);
    ctr->setCounterSize(4);
    ctr->encrypt(bytes, scratch, numBytes);
}
#ifndef HAS_CUSTOM_CRYPTO_ENGINE
CryptoEngine *crypto = new CryptoEngine;
#endif

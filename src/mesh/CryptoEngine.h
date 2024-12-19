#pragma once
#include "AES.h"
#include "CTR.h"
#include "MeshTypes.h"
#include "concurrency/LockGuard.h"
#include "configuration.h"
#include "mesh-pb-constants.h"
#include <Arduino.h>

extern concurrency::Lock *cryptLock;

struct CryptoKey {
    uint8_t bytes[32];

    /// # of bytes, or -1 to mean "invalid key - do not use"
    int8_t length;
};

/**
 * see docs/software/crypto.md for details.
 *
 */

#define MAX_BLOCKSIZE 256
#define TEST_CURVE25519_FIELD_OPS // Exposes Curve25519::isWeakPoint() for testing keys

class CryptoEngine
{
  public:
    using extra_nonce_t = uint32_t;

#if !(MESHTASTIC_EXCLUDE_PKI)
    static constexpr size_t kTagSizeM = 8; // M value from RFC 3610
    static constexpr size_t kCurve25519Overhead = kTagSizeM + sizeof(extra_nonce_t);
    uint8_t public_key[32] = {0};
#endif

    virtual ~CryptoEngine() {}
#if !(MESHTASTIC_EXCLUDE_PKI)
#if !(MESHTASTIC_EXCLUDE_PKI_KEYGEN)
    virtual void generateKeyPair(uint8_t *pubKey, uint8_t *privKey);
    virtual bool regeneratePublicKey(uint8_t *pubKey, uint8_t *privKey);

#endif
    void clearKeys();
    void setDHPrivateKey(uint8_t *_private_key);
    virtual bool encryptCurve25519(NodeNum toNode, NodeNum fromNode, const meshtastic_UserLite_public_key_t remotePublic,
                                   uint32_t packetId, size_t numBytes, const uint8_t *bytes, uint8_t *bytesOut);
    virtual bool decryptCurve25519(NodeNum fromNode, const meshtastic_UserLite_public_key_t remotePublic, uint32_t packetId,
                                   size_t numBytes, const uint8_t *bytes, uint8_t *bytesOut);
    virtual bool setDHPublicKey(const uint8_t *publicKey);
    virtual void hash(uint8_t *bytes, size_t numBytes);

    virtual void aesSetKey(const uint8_t *key, size_t key_len);

    virtual void aesEncrypt(uint8_t *in, uint8_t *out);
    AESSmall256 *aes = NULL;

#endif

    /**
     * Set the key used for encrypt, decrypt.
     *
     * As a special case: If all bytes are zero, we assume _no encryption_ and send all data in cleartext.
     *
     * @param numBytes must be 16 (AES128), 32 (AES256) or 0 (no crypt)
     * @param bytes a _static_ buffer that will remain valid for the life of this crypto instance (i.e. this class will cache the
     * provided pointer)
     */
    virtual void setKey(const CryptoKey &k);

    /**
     * Encrypt a packet
     *
     * @param bytes is updated in place
     */
    virtual void encryptPacket(NodeNum fromNode, uint32_t packetId, size_t numBytes, uint8_t *bytes);
    virtual void decrypt(NodeNum fromNode, uint32_t packetId, size_t numBytes, uint8_t *bytes);
    virtual void encryptAESCtr(CryptoKey key, uint8_t *nonce, size_t numBytes, uint8_t *bytes);
#ifndef PIO_UNIT_TESTING
  protected:
#endif
    CryptoKey key = {};
    CTRCommon *ctr = NULL;
#if !(MESHTASTIC_EXCLUDE_PKI)
    uint8_t shared_key[32] = {0};
    uint8_t private_key[32] = {0};
#endif
};

extern CryptoEngine *crypto;
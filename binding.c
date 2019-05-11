#include <assert.h>
#include <math.h>
#include <node_api.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <stdint.h>
#include <stdlib.h>

#define RESOURCE_NAME "@ronomon/crypto-async"

#define E_AAD "aad must be a buffer"
#define E_AAD_INVALID "aadSize invalid"
#define E_AAD_OFFSET "aadOffset must be an unsigned integer"
#define E_AAD_RANGE "aadOffset + aadSize > aad.length"
#define E_AAD_SIZE "aadSize must be an unsigned integer"
#define E_ALGORITHM "algorithm must be a string"
#define E_ALGORITHM_DISABLED "algorithm disabled"
#define E_ALGORITHM_UNKNOWN "algorithm unknown"
#define E_ARGUMENTS "wrong number of arguments"
#define E_BUFFER_LENGTH "buffer.length > INT_MAX"
#define E_CALLBACK "callback must be a function"
#define E_CANCELLED "asynchronous task was cancelled"
#define E_CORRUPT "corrupt"
#define E_ENCRYPT "encrypt must be 0 or 1"
#define E_IV "iv must be a buffer"
#define E_IV_INVALID "ivSize invalid"
#define E_IV_OFFSET "ivOffset must be an unsigned integer"
#define E_IV_RANGE "ivOffset + ivSize > iv.length"
#define E_IV_SIZE "ivSize must be an unsigned integer"
#define E_KEY "key must be a buffer"
#define E_KEY_EXTERNAL "key must be created using the key(buffer) method"
#define E_KEY_INVALID "keySize invalid"
#define E_KEY_OFFSET "keyOffset must be an unsigned integer"
#define E_KEY_RANGE "keyOffset + keySize > key.length"
#define E_KEY_SIZE "keySize must be an unsigned integer"
#define E_OOM "out of memory"
#define E_SIGN "sign must be 0 or 1"
#define E_SOURCE "source must be a buffer"
#define E_SOURCE_OFFSET "sourceOffset must be an unsigned integer"
#define E_SOURCE_RANGE "sourceOffset + sourceSize > source.length"
#define E_SOURCE_SIZE "sourceSize must be an unsigned integer"
#define E_TAG "tag must be a buffer"
#define E_TAG_INVALID "tagSize invalid"
#define E_TAG_OFFSET "tagOffset must be an unsigned integer"
#define E_TAG_RANGE "tagOffset + tagSize > tag.length"
#define E_TAG_SIZE "tagSize must be an unsigned integer"
#define E_TARGET "target must be a buffer"
#define E_TARGET_OFFSET "targetOffset must be an unsigned integer"
#define E_TARGET_RANGE "targetOffset + targetSize > target.length"

#define FLAG_CIPHER 1
#define FLAG_HASH 2
#define FLAG_HMAC 4
#define FLAG_SIGNATURE 8

#define OK(call)                                                               \
  assert((call) == napi_ok);

#define THROW(env, message)                                                    \
  do {                                                                         \
    napi_throw_error((env), NULL, (message));                                  \
    return NULL;                                                               \
  } while (0)

static int arg_buf(
  napi_env env,
  napi_value value,
  unsigned char** buffer,
  int* length,
  const char* error
) {
  assert(*buffer == NULL);
  assert(*length == 0);
  bool is_buffer;
  OK(napi_is_buffer(env, value, &is_buffer));
  if (!is_buffer) {
    napi_throw_error(env, NULL, error);
    return 0;
  }
  size_t size = 0;
  OK(napi_get_buffer_info(env, value, (void**) buffer, &size));
  assert(*buffer != NULL);
  if (size > INT_MAX) {
    napi_throw_error(env, NULL, E_BUFFER_LENGTH);
    return 0;
  }
  *length = (int) size;
  assert(*length >= 0);
  return 1;
}

static int arg_int(
  napi_env env,
  napi_value value,
  int* integer,
  const char* error
) {
  assert(*integer == 0);
  double temp = 0;
  if (
    // We get the value as a double so we can check for NaN, Infinity and float:
    // https://github.com/nodejs/node/issues/26323
    napi_get_value_double(env, value, &temp) != napi_ok ||
    temp < 0 ||
    // NaN:
    isnan(temp) ||
    // Infinity, also prevent UB for double->int cast below:
    // https://groups.google.com/forum/#!topic/comp.lang.c/rhPzd4bgKJk
    temp > INT_MAX ||
    // Float:
    (double) ((int) temp) != temp
  ) {
    napi_throw_error(env, NULL, error);
    return 0;
  }
  *integer = (int) temp;
  assert(*integer >= 0);
  return 1;
}

static int arg_str(
  napi_env env,
  napi_value value,
  char* string,
  const size_t length,
  const char* error
) {
  size_t out = 0;
  if (napi_get_value_string_utf8(env, value, string, length, &out) != napi_ok) {
    napi_throw_error(env, NULL, error);
    return 0;
  }
  return 1;
}

static int cipher_aead(const EVP_CIPHER* evp_cipher) {
  assert(evp_cipher);
  if (EVP_CIPHER_nid(evp_cipher) == NID_chacha20_poly1305) return 1;
  const int mode = EVP_CIPHER_mode(evp_cipher);
  if (mode == EVP_CIPH_GCM_MODE) return 1;
  if (mode == EVP_CIPH_OCB_MODE) return 1;
  return 0;
}

static int cipher_supported(const EVP_CIPHER* evp_cipher) {
  // CCM is slow, macs then encrypts, and has a complicated OpenSSL interface.
  // CBC has a poor track record, and leaves padding after the decrypted target.
  int nid = EVP_CIPHER_nid(evp_cipher);
  if (nid == NID_chacha20_poly1305) return 1;
  if (nid == NID_chacha20) return 1;
  int mode = EVP_CIPHER_mode(evp_cipher);
  if (mode == EVP_CIPH_CTR_MODE) return 1;
  if (mode == EVP_CIPH_GCM_MODE) return 1;
  // Disable OCB (patented):
  // if (mode == EVP_CIPH_OCB_MODE) return 1;
  return 0;
}

static int cipher_target_size(
  const EVP_CIPHER* evp_cipher,
  const int encrypt,
  const int source_size
) {
  assert(evp_cipher);
  assert(encrypt == 0 || encrypt == 1);
  assert(source_size >= 0);
  const int block_size = EVP_CIPHER_block_size(evp_cipher);
  assert(block_size >= 0);
  if (block_size == 1) return source_size;
  if (encrypt) {
    // "The amount of data written depends on the block alignment of the
    // encrypted data: as a result the amount of data written may be anything
    // from zero bytes to (inl + cipher_block_size - 1)."

    // We DO NOT subtract 1 according to the OpenSSL documentation above because
    // a `source_size` of 0 plus a `block_size` of 16 minus 1 would be
    // 15, but AES-CBC, for example, will write a minimum of `block_size`.
    //
    // Therefore, OpenSSL's explanation is only half-true, instead:
    // 1. Maximum `target_size` must be aligned to `block_size`.
    // 2. Maximum `target_size` must be at least `block_size`.
    //
    // We must adjust `target_size` once we know the final write offset.
    assert(block_size <= INT_MAX - source_size);
    return source_size + block_size;
  } else {
    // "The parameters and restrictions are identical to the encryption
    // operations except that if padding is enabled the decrypted data buffer
    // out passed to EVP_DecryptUpdate() should have sufficient room for
    // (inl + cipher_block_size) bytes, unless the cipher block size is 1 in
    // which case inl bytes is sufficient."
    assert(block_size <= INT_MAX - source_size);
    return source_size + block_size;
  }
}

static int cipher_valid_aad_size(
  const EVP_CIPHER* evp_cipher,
  const int aad_size
) {
  assert(evp_cipher);
  assert(aad_size >= 0);
  if (!cipher_aead(evp_cipher) && aad_size != 0) return 0;
  return 1;
}

static int cipher_valid_iv_size(
  const EVP_CIPHER* evp_cipher,
  const int iv_size
) {
  assert(evp_cipher);
  assert(iv_size >= 0);
  // OpenSSL allows variable length IVs for AEAD ciphers:
  // "The maximum nonce length is 16 (CHACHA_CTR_SIZE, i.e. 128-bits)."
  // "For OCB mode the maximum is 15."
  //
  // However, OpenSSL had CVE-2019-1543 because of this for ChaCha20-Poly1305:
  // https://www.openssl.org/news/secadv/20190306.txt
  // https://github.com/openssl/openssl/issues/8345
  //
  // Allowing variable length IVs also opens the door for further nonce reuse:
  // https://github.com/openssl/openssl/pull/8406#issuecomment-470615087
  //
  // We therefore require all IVs to be the default length.
  // Anything else is a recipe for disaster.
  if (iv_size == EVP_CIPHER_iv_length(evp_cipher)) return 1;
  return 0;
}

static int cipher_valid_key_size(
  const EVP_CIPHER* evp_cipher,
  const int key_size
) {
  assert(evp_cipher);
  assert(key_size >= 0);
  if (key_size == EVP_CIPHER_key_length(evp_cipher)) return 1;
  return 0;
}

static int cipher_valid_tag_size(
  const EVP_CIPHER* evp_cipher,
  const int tag_size
) {
  assert(evp_cipher);
  assert(tag_size >= 0);
  if (!cipher_aead(evp_cipher)) {
    if (tag_size != 0) return 0;
    return 1;
  }
  if (EVP_CIPHER_nid(evp_cipher) == NID_chacha20_poly1305) {
    // "taglen must be between 1 and 16 (POLY1305_BLOCK_SIZE) inclusive."
    if (tag_size < 1 || tag_size > 16) return 0;
    return 1;
  }
  const int mode = EVP_CIPHER_mode(evp_cipher);
  if (mode == EVP_CIPH_GCM_MODE) {
    // "The bit length of the tag, denoted t, is a security parameter, as
    // discussed in Appendix B. In general, t may be any one of the following
    // five values: 128, 120, 112, 104, or 96. For certain applications, t may
    // be 64 or 32; guidance for the use of these two tag lengths, including
    // requirements on the length of the input data and the lifetime of the key
    // in these cases, is given in Appendix C. An implementation shall not
    // support values for t that are different from the seven choices in the
    // preceding paragraph. An implementation may restrict its support to as few
    // as one of these values."
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/
    // nistspecialpublication800-38d.pdf#page=17
    if (!(tag_size >= 12 && tag_size <= 16) && tag_size != 8 && tag_size != 4) {
      return 0;
    }
    return 1;
  }
  if (mode == EVP_CIPH_OCB_MODE) {
    // "taglen must be between 1 and 16 inclusive."
    if (tag_size < 1 || tag_size > 16) return 0;
    return 1;
  }
  if (tag_size < 1) return 0;
  // Defer validation to OpenSSL.
  return 1;
}

static const char* execute_cipher(
  const int nid,
  const int encrypt,
  const unsigned char* key,
  const int key_size,
  const unsigned char* iv,
  const int iv_size,
  const unsigned char* source,
  const int source_size,
  unsigned char* target,
  int* target_size,
  const unsigned char* aad,
  const int aad_size,
  unsigned char* tag,
  const int tag_size
) {
  const EVP_CIPHER* evp_cipher = EVP_get_cipherbynid(nid);
  if (!evp_cipher) return "nid invalid";
  assert(encrypt == 0 || encrypt == 1);
  assert(key != NULL);
  assert(iv != NULL);
  assert(source != NULL);
  assert(target != NULL);
  assert(aad != NULL);
  assert(tag != NULL);
  assert(cipher_valid_key_size(evp_cipher, key_size));
  assert(cipher_valid_iv_size(evp_cipher, iv_size));
  assert(source_size >= 0);
  assert(*target_size >= 0);
  int aead = cipher_aead(evp_cipher);
  assert(cipher_valid_aad_size(evp_cipher, aad_size));
  assert(cipher_valid_tag_size(evp_cipher, tag_size));

  // Initialize the context without setting the key or IV:
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return "allocation failed";
  if (!EVP_CipherInit_ex(ctx, evp_cipher, NULL, NULL, NULL, encrypt)) {
    EVP_CIPHER_CTX_free(ctx);
    return "initialization failed";
  }

  // Disable padding to prevent an accidental padding oracle:
  // https://blog.cloudflare.com/padding-oracles-and-the-decline-of-
  // cbc-mode-ciphersuites/
  if (!EVP_CIPHER_CTX_set_padding(ctx, 0)) {
    EVP_CIPHER_CTX_free(ctx);
    return "set padding failed";
  }

  // Set the tag length only for OCB before encryption (and decryption):
  if (aead && EVP_CIPHER_mode(evp_cipher) == EVP_CIPH_OCB_MODE) {
    // "In OCB mode, calling this before encryption with tag set to NULL sets
    // the tag length. If this is not called prior to encryption, a default tag
    // length is used."

    // Contrary to the OpenSSL docs, this is also necessary before decryption.
    // https://github.com/openssl/openssl/issues/8331
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_size, NULL)) {
      EVP_CIPHER_CTX_free(ctx);
      return "tagSize invalid";
    }
  }

  // Set the tag and tag length before decryption:
  if (aead && !encrypt) {
    // GCM and OCB:
    // "Sets the expected tag to taglen bytes from tag. The tag length can only
    // be set before specifying an IV. taglen must be between 1 and 16
    // inclusive.
    //
    // For GCM, this call is only valid when decrypting data.
    // For OCB, this call is valid when decrypting data to set the expected tag,
    // and before encryption to set the desired tag length.
    // For OCB AES, the default tag length is 16 (i.e. 128 bits). It is also the
    // maximum tag length for OCB."
    
    // ChaCha20-Poly1305:
    // "Sets the expected tag to taglen bytes from tag. The tag length can only
    // be set before specifying an IV. taglen must be between 1 and 16
    // (POLY1305_BLOCK_SIZE) inclusive. This call is only valid when decrypting
    // data."
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_size, tag)) {
      EVP_CIPHER_CTX_free(ctx);
      return "tag initialization failed";
    }
  }

  // Assert key and IV length:
  assert(key_size == EVP_CIPHER_key_length(evp_cipher));
  assert(iv_size == EVP_CIPHER_iv_length(evp_cipher));

  // Set the key and IV:
  // "The operation performed depends on the value of the enc parameter. It
  // should be set to 1 for encryption, 0 for decryption and -1 to leave the
  // value unchanged (the actual value of 'enc' being supplied in a previous
  // call)."
  if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, -1)) {
    EVP_CIPHER_CTX_free(ctx);
    return "key and iv initialization failed";
  }

  // Set the additional authenticated data when encrypting and decrypting:
  if (aead && aad_size > 0) {
    // "To specify additional authenticated data (AAD), a call to
    // EVP_CipherUpdate(), EVP_EncryptUpdate() or EVP_DecryptUpdate() should be
    // made with the output parameter out set to NULL."
    int aad_update_size = 0;
    if (!EVP_CipherUpdate(ctx, NULL, &aad_update_size, aad, aad_size)) {
      EVP_CIPHER_CTX_free(ctx);
      return "aad initialization failed";
    }
    // OCB rounds outlen down to the nearest multiple of block size:
    // https://github.com/openssl/openssl/issues/8310
    const int block_size = EVP_CIPHER_block_size(evp_cipher);
    assert(aad_update_size == (aad_size / block_size) * block_size);
  }

  // Update and finalize:
  int target_offset = 0;
  int update_size = 0;
  int final_size = 0;
  if (!EVP_CipherUpdate(ctx, target, &update_size, source, source_size)) {
    EVP_CIPHER_CTX_free(ctx);
    return "update failed";
  }
  assert(update_size >= 0);
  assert(update_size <= INT_MAX - target_offset);
  target_offset += update_size;
  if (!EVP_CipherFinal_ex(ctx, target + target_offset, &final_size)) {
    EVP_CIPHER_CTX_free(ctx);
    if (aead && !encrypt) {
      // "When decrypting, the return value of EVP_CipherFinal() indicates if
      // the operation was successful. If it does not indicate success, the
      // authentication operation has failed and any output data MUST NOT be
      // used as it is corrupted."
      return E_CORRUPT;
    }
    return "finalization failed";
  }
  assert(final_size >= 0);
  assert(final_size <= INT_MAX - target_offset);
  target_offset += final_size;

  // Detect an out-of-bounds write in case it ever happens (it never should):
  // We already do range checks before writing to buffers to prevent this.
  // This is defense in depth.
  assert(target_offset <= *target_size);

  // Set target_size to what was actually written:
  *target_size = target_offset;

  // Get the tag after encrypting:
  if (aead && encrypt) {
    // GCM and OCB:
    // "Writes taglen bytes of the tag value to the buffer indicated by tag.
    // This call can only be made when encrypting data and after all data has
    // been processed (e.g. after an EVP_EncryptFinal() call).
    //
    // For OCB mode, the taglen must either be 16 or the value previously set
    // via EVP_CTRL_OCB_SET_TAGLEN."
    
    // ChaCha20-Poly1305:
    // "taglen specified here must be 16 (POLY1305_BLOCK_SIZE, i.e. 128-bits) or
    // less."
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_size, tag)) {
      EVP_CIPHER_CTX_free(ctx);
      return "tag finalization failed";
    };
  }

  EVP_CIPHER_CTX_free(ctx);
  return NULL;
}

static const char* execute_hash(
  const int nid,
  const unsigned char* source,
  const int source_size,
  unsigned char* target
) {
  const EVP_MD* evp_md = EVP_get_digestbynid(nid);
  if (!evp_md) return "nid invalid";
  assert(source != NULL);
  assert(target != NULL);
  assert(source_size >= 0);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) return "allocation failed";
  if (!EVP_DigestInit_ex(ctx, evp_md, NULL)) {
    EVP_MD_CTX_free(ctx);
    return "initialization failed";
  }
  if (!EVP_DigestUpdate(ctx, source, source_size)) {
    EVP_MD_CTX_free(ctx);
    return "update failed";
  }
  if (!EVP_DigestFinal_ex(ctx, target, NULL)) {
    EVP_MD_CTX_free(ctx);
    return "finalization failed";
  }
  EVP_MD_CTX_free(ctx);
  return NULL;
}

static const char* execute_hmac(
  const int nid,
  const unsigned char* key,
  const int key_size,
  const unsigned char* source,
  const int source_size,
  unsigned char* target
) {
  const EVP_MD* evp_md = EVP_get_digestbynid(nid);
  if (!evp_md) return "nid invalid";
  assert(key != NULL);
  assert(source != NULL);
  assert(target != NULL);
  assert(key_size >= 0);
  assert(source_size >= 0);
  HMAC_CTX *ctx = HMAC_CTX_new();
  if (!ctx) return "allocation failed";
  if (!HMAC_Init_ex(ctx, key, key_size, evp_md, NULL)) {
    HMAC_CTX_free(ctx);
    return "initialization failed";
  }
  if (!HMAC_Update(ctx, source, source_size)) {
    HMAC_CTX_free(ctx);
    return "update failed";
  }
  if (!HMAC_Final(ctx, target, NULL)) {
    HMAC_CTX_free(ctx);
    return "finalization failed";
  }
  HMAC_CTX_free(ctx);
  return NULL;
}

static const char* execute_signature(
  const int nid,
  const int sign,
  EVP_PKEY* key,
  const unsigned char* source,
  const int source_size,
  unsigned char* target,
  int* target_size
) {
  const EVP_MD* evp_md = EVP_get_digestbynid(nid);
  if (!evp_md) {
    return "nid invalid";
  }
  EVP_MD_CTX* ctx = EVP_MD_CTX_create();
  if (sign == 1) {
    if (EVP_DigestSignInit(ctx, NULL, evp_md, NULL, key) <= 0) {
      EVP_MD_CTX_free(ctx);
      return "initialization failed";
    }
    if (EVP_DigestSignUpdate(ctx, source, source_size) <= 0) {
      EVP_MD_CTX_free(ctx);
      return "update failed";
    }
    size_t final_size = *target_size;
    if (EVP_DigestSignFinal(ctx, target, &final_size) <= 0) {
      EVP_MD_CTX_free(ctx);
      return "finalization failed";
    }
    EVP_MD_CTX_free(ctx);
    *target_size = final_size;
  } else {
    if (EVP_DigestVerifyInit(ctx, NULL, evp_md, NULL, key) <= 0) {
      EVP_MD_CTX_free(ctx);
      return "initialization failed";
    }
    if (EVP_DigestVerifyUpdate(ctx, source, source_size) <= 0) {
      EVP_MD_CTX_free(ctx);
      return "update failed";
    }
    size_t final_size = *target_size;
    int verification_status = EVP_DigestVerifyFinal(ctx, target, final_size);
    if (verification_status == 1) {
      EVP_MD_CTX_free(ctx);
    } else {
      *target_size = 0;
      EVP_MD_CTX_free(ctx);
    }
  }
  return NULL;
}

static int range(
  napi_env env,
  const int offset,
  const int size,
  const int length,
  const char* error
) {
  assert(offset >= 0);
  assert(size >= 0);
  assert(length >= 0);
  // We must avoid undefined behavior from signed overflow before testing range:
  if (size > INT_MAX - offset) {
    napi_throw_error(env, NULL, error);
    return 0;
  }
  // Signed overflow on some compilers may wrap, assert as last line of defense:
  assert(offset + size >= 0);
  if (offset + size > length) {
    napi_throw_error(env, NULL, error);
    return 0;
  }
  return 1;
}

struct task_data {
  int flags;
  int nid;
  int encrypt;
  unsigned char* key;
  unsigned char* iv;
  unsigned char* source;
  unsigned char* target;
  unsigned char* aad;
  unsigned char* tag;
  int key_size;
  int iv_size;
  int source_size;
  int target_size;
  int aad_size;
  int tag_size;
  napi_ref ref_key;
  napi_ref ref_iv;
  napi_ref ref_source;
  napi_ref ref_target;
  napi_ref ref_aad;
  napi_ref ref_tag;
  napi_ref ref_callback;
  napi_async_work async_work;
  const char* error;
};

void task_execute(napi_env env, void* data) {
  struct task_data* task = data;
  assert(task->flags > 0);
  if (task->flags & FLAG_CIPHER) {
    task->error = execute_cipher(
      task->nid,
      task->encrypt,
      task->key,
      task->key_size,
      task->iv,
      task->iv_size,
      task->source,
      task->source_size,
      task->target,
      &task->target_size,
      task->aad,
      task->aad_size,
      task->tag,
      task->tag_size
    );
  } else if (task->flags & FLAG_HASH) {
    task->error = execute_hash(
      task->nid,
      task->source,
      task->source_size,
      task->target
    );
  } else if (task->flags & FLAG_HMAC) {
    task->error = execute_hmac(
      task->nid,
      task->key,
      task->key_size,
      task->source,
      task->source_size,
      task->target
    );
  } else if (task->flags & FLAG_SIGNATURE) {
    napi_value key_external;
    if (napi_get_reference_value(env, task->ref_key, &key_external) != napi_ok) {
      printf("invalid private key");
      abort();
      return;
    }
    void *key;
    if (napi_get_value_external(env, key_external, &key)) {
      printf("invalid private key");
      abort();
      return;
    }
    task->error = execute_signature(
      task->nid,
      task->encrypt,
      (EVP_PKEY*) key,
      task->source,
      task->source_size,
      task->target,
      &task->target_size
    );
  } else {
    printf("unrecognized task->flags=%i\n", task->flags);
    abort();
  }
}

void task_complete(napi_env env, napi_status status, void* data) {
  struct task_data* task = data;
  if (status == napi_cancelled) {
    task->error = E_CANCELLED;
  } else {
    assert(status == napi_ok);
  }
  int argc = 0;
  napi_value argv[2];
  if (task->error) {
    argc = 1;
    napi_value message;
    OK(napi_create_string_utf8(env, task->error, NAPI_AUTO_LENGTH, &message));
    OK(napi_create_error(env, NULL, message, &argv[0]));
  } else {
    argc = 2;
    OK(napi_get_undefined(env, &argv[0]));
    OK(napi_create_int64(env, task->target_size, &argv[1]));
  }
  napi_value scope;
  OK(napi_get_global(env, &scope));
  napi_value callback;
  OK(napi_get_reference_value(env, task->ref_callback, &callback));
  // Do not assert the return status of napi_call_function():
  // If the callback throws then the return status will not be napi_ok.
  napi_call_function(env, scope, callback, argc, argv, NULL);
  if (task->ref_key) OK(napi_delete_reference(env, task->ref_key));
  if (task->ref_iv) OK(napi_delete_reference(env, task->ref_iv));
  assert(task->ref_source != NULL);
  assert(task->ref_target != NULL);
  OK(napi_delete_reference(env, task->ref_source));
  OK(napi_delete_reference(env, task->ref_target));
  if (task->ref_aad) OK(napi_delete_reference(env, task->ref_aad));
  if (task->ref_tag) OK(napi_delete_reference(env, task->ref_tag));
  assert(task->ref_callback != NULL);
  assert(task->async_work != NULL);
  OK(napi_delete_reference(env, task->ref_callback));
  OK(napi_delete_async_work(env, task->async_work));
  free(task);
  task = NULL;
}

static napi_value task_create(
  napi_env env,
  int flags,
  int nid,
  int encrypt,
  unsigned char* key,
  unsigned char* iv,
  unsigned char* source,
  unsigned char* target,
  unsigned char* aad,
  unsigned char* tag,
  int key_size,
  int iv_size,
  int source_size,
  int target_size,
  int aad_size,
  int tag_size,
  napi_value ref_key,
  napi_value ref_iv,
  napi_value ref_source,
  napi_value ref_target,
  napi_value ref_aad,
  napi_value ref_tag,
  napi_value ref_callback
) {
  napi_valuetype callback_type;
  OK(napi_typeof(env, ref_callback, &callback_type));
  if (callback_type != napi_function) THROW(env, E_CALLBACK);
  assert(flags > 0);
  assert(encrypt == 0 || encrypt == 1);
  assert(source != NULL);
  assert(target != NULL);
  assert(key_size >= 0);
  assert(iv_size >= 0);
  assert(source_size >= 0);
  assert(target_size >= 0);
  assert(aad_size >= 0);
  assert(tag_size >= 0);
  assert(ref_source != NULL);
  assert(ref_target != NULL);
  assert(ref_callback != NULL);
  struct task_data* task = calloc(1, sizeof(struct task_data));
  if (!task) THROW(env, E_OOM);
  task->flags = flags;
  task->nid = nid;
  task->encrypt = encrypt;
  task->key = key;
  task->iv = iv;
  task->source = source;
  task->target = target;
  task->aad = aad;
  task->tag = tag;
  task->key_size = key_size;
  task->iv_size = iv_size;
  task->source_size = source_size;
  task->target_size = target_size;
  task->aad_size = aad_size;
  task->tag_size = tag_size;
  assert(task->ref_key == NULL);
  assert(task->ref_iv == NULL);
  assert(task->ref_source == NULL);
  assert(task->ref_target == NULL);
  assert(task->ref_aad == NULL);
  assert(task->ref_tag == NULL);
  assert(task->ref_callback == NULL);
  assert(task->error == NULL);
  if (ref_key) OK(napi_create_reference(env, ref_key, 1, &task->ref_key));
  if (ref_iv) OK(napi_create_reference(env, ref_iv, 1, &task->ref_iv));
  OK(napi_create_reference(env, ref_source, 1, &task->ref_source));
  OK(napi_create_reference(env, ref_target, 1, &task->ref_target));
  if (ref_aad) OK(napi_create_reference(env, ref_aad, 1, &task->ref_aad));
  if (ref_tag) OK(napi_create_reference(env, ref_tag, 1, &task->ref_tag));
  OK(napi_create_reference(env, ref_callback, 1, &task->ref_callback));
  napi_value name;
  OK(napi_create_string_utf8(env, RESOURCE_NAME, NAPI_AUTO_LENGTH, &name));
  OK(napi_create_async_work(
    env,
    NULL,
    name,
    task_execute,
    task_complete,
    task,
    &task->async_work
  ));
  OK(napi_queue_async_work(env, task->async_work));
  return NULL;
}

static napi_value cipher(napi_env env, napi_callback_info info) {
  size_t argc = 20;
  napi_value argv[20];
  OK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc != 19 && argc != 20) THROW(env, E_ARGUMENTS);
  char algorithm[32];
  int encrypt = 0;
  unsigned char* key = NULL;
  unsigned char* iv = NULL;
  unsigned char* source = NULL;
  unsigned char* target = NULL;
  unsigned char* aad = NULL;
  unsigned char* tag = NULL;
  int key_length = 0;
  int iv_length = 0;
  int source_length = 0;
  int target_length = 0;
  int aad_length = 0;
  int tag_length = 0;
  int key_offset = 0;
  int iv_offset = 0;
  int source_offset = 0;
  int target_offset = 0;
  int aad_offset = 0;
  int tag_offset = 0;
  int key_size = 0;
  int iv_size = 0;
  int source_size = 0;
  int target_size = 0;
  int aad_size = 0;
  int tag_size = 0;
  if (!arg_str(env, argv[0], algorithm, 32, E_ALGORITHM)) return NULL;
  const EVP_CIPHER* evp_cipher = EVP_get_cipherbyname(algorithm);
  if (!evp_cipher) THROW(env, E_ALGORITHM_UNKNOWN);
  if (!cipher_supported(evp_cipher)) THROW(env, E_ALGORITHM_DISABLED);
  // We avoid EVP_CIPHER_type() since this returns `NID_undef` for some ciphers:
  int nid = EVP_CIPHER_nid(evp_cipher);
  assert(nid != NID_undef);
  if (!arg_int(env, argv[1], &encrypt, E_ENCRYPT)) return NULL;
  if (encrypt != 0 && encrypt != 1) THROW(env, E_ENCRYPT);
  if (
    !arg_buf(env, argv[2], &key, &key_length, E_KEY) ||
    !arg_int(env, argv[3], &key_offset, E_KEY_OFFSET) ||
    !arg_int(env, argv[4], &key_size, E_KEY_SIZE) ||
    !arg_buf(env, argv[5], &iv, &iv_length, E_IV) ||
    !arg_int(env, argv[6], &iv_offset, E_IV_OFFSET) ||
    !arg_int(env, argv[7], &iv_size, E_IV_SIZE) ||
    !arg_buf(env, argv[8], &source, &source_length, E_SOURCE) ||
    !arg_int(env, argv[9], &source_offset, E_SOURCE_OFFSET) ||
    !arg_int(env, argv[10], &source_size, E_SOURCE_SIZE) ||
    !arg_buf(env, argv[11], &target, &target_length, E_TARGET) ||
    !arg_int(env, argv[12], &target_offset, E_TARGET_OFFSET) ||
    !arg_buf(env, argv[13], &aad, &aad_length, E_AAD) ||
    !arg_int(env, argv[14], &aad_offset, E_AAD_OFFSET) ||
    !arg_int(env, argv[15], &aad_size, E_AAD_SIZE) ||
    !arg_buf(env, argv[16], &tag, &tag_length, E_TAG) ||
    !arg_int(env, argv[17], &tag_offset, E_TAG_OFFSET) ||
    !arg_int(env, argv[18], &tag_size, E_TAG_SIZE)
  ) {
    return NULL;
  }
  if (
    !range(env, key_offset, key_size, key_length, E_KEY_RANGE) ||
    !range(env, iv_offset, iv_size, iv_length, E_IV_RANGE) ||
    !range(env, source_offset, source_size, source_length, E_SOURCE_RANGE)
  ) {
    return NULL;
  }
  target_size = cipher_target_size(evp_cipher, encrypt, source_size);
  assert(target_size >= 0);
  if (
    !range(env, target_offset, target_size, target_length, E_TARGET_RANGE) ||
    !range(env, aad_offset, aad_size, aad_length, E_AAD_RANGE) ||
    !range(env, tag_offset, tag_size, tag_length, E_TAG_RANGE)
  ) {
    return NULL;
  }
  if (!cipher_valid_key_size(evp_cipher, key_size)) THROW(env, E_KEY_INVALID);
  if (!cipher_valid_iv_size(evp_cipher, iv_size)) THROW(env, E_IV_INVALID);
  if (!cipher_valid_aad_size(evp_cipher, aad_size)) THROW(env, E_AAD_INVALID);
  if (!cipher_valid_tag_size(evp_cipher, tag_size)) THROW(env, E_TAG_INVALID);
  key += key_offset;
  iv += iv_offset;
  source += source_offset;
  target += target_offset;
  aad += aad_offset;
  tag += tag_offset;
  if (argc == 19) {
    const char* error = execute_cipher(
      nid,
      encrypt,
      key,
      key_size,
      iv,
      iv_size,
      source,
      source_size,
      target,
      &target_size,
      aad,
      aad_size,
      tag,
      tag_size
    );
    if (error) THROW(env, error);
    napi_value result;
    OK(napi_create_int64(env, target_size, &result));
    return result;
  }
  return task_create(
    env,            // env
    FLAG_CIPHER,    // flags
    nid,            // nid
    encrypt,        // encrypt
    key,            // key
    iv,             // iv
    source,         // source
    target,         // target
    aad,            // aad
    tag,            // tag
    key_size,       // key_size
    iv_size,        // iv_size
    source_size,    // source_size
    target_size,    // target_size
    aad_size,       // aad_size
    tag_size,       // tag_size
    argv[2],        // ref_key
    argv[5],        // ref_iv
    argv[8],        // ref_source
    argv[11],       // ref_target
    argv[13],       // ref_aad
    argv[16],       // ref_tag
    argv[19]        // ref_callback
  );
}

static napi_value hash(napi_env env, napi_callback_info info) {
  size_t argc = 7;
  napi_value argv[7];
  OK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc != 6 && argc != 7) THROW(env, E_ARGUMENTS);
  char algorithm[32];
  unsigned char* source = NULL;
  unsigned char* target = NULL;
  int source_length = 0;
  int target_length = 0;
  int source_offset = 0;
  int target_offset = 0;
  int source_size = 0;
  int target_size = 0;
  if (!arg_str(env, argv[0], algorithm, 32, E_ALGORITHM)) return NULL;
  const EVP_MD* evp_md = EVP_get_digestbyname(algorithm);
  if (!evp_md) THROW(env, E_ALGORITHM_UNKNOWN);
  int nid = EVP_MD_type(evp_md);
  assert(nid != NID_undef);
  target_size = EVP_MD_size(evp_md);
  assert(target_size > 0);
  if (
    !arg_buf(env, argv[1], &source, &source_length, E_SOURCE) ||
    !arg_int(env, argv[2], &source_offset, E_SOURCE_OFFSET) ||
    !arg_int(env, argv[3], &source_size, E_SOURCE_SIZE) ||
    !arg_buf(env, argv[4], &target, &target_length, E_TARGET) ||
    !arg_int(env, argv[5], &target_offset, E_TARGET_OFFSET) ||
    !range(env, source_offset, source_size, source_length, E_SOURCE_RANGE) ||
    !range(env, target_offset, target_size, target_length, E_TARGET_RANGE)
  ) {
    return NULL;
  }
  source += source_offset;
  target += target_offset;
  if (argc == 6) {
    const char* error = execute_hash(nid, source, source_size, target);
    if (error) THROW(env, error);
    napi_value result;
    OK(napi_create_int64(env, target_size, &result));
    return result;
  }
  return task_create(
    env,            // env
    FLAG_HASH,      // flags
    nid,            // nid
    0,              // encrypt
    NULL,           // key
    NULL,           // iv
    source,         // source
    target,         // target
    NULL,           // aad
    NULL,           // tag
    0,              // key_size
    0,              // iv_size
    source_size,    // source_size
    target_size,    // target_size
    0,              // aad_size
    0,              // tag_size
    NULL,           // ref_key
    NULL,           // ref_iv
    argv[1],        // ref_source
    argv[4],        // ref_target
    NULL,           // ref_aad
    NULL,           // ref_tag
    argv[6]         // ref_callback
  );
}

static napi_value hmac(napi_env env, napi_callback_info info) {
  size_t argc = 10;
  napi_value argv[10];
  OK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc != 9 && argc != 10) THROW(env, E_ARGUMENTS);
  char algorithm[32];
  unsigned char* key = NULL;
  unsigned char* source = NULL;
  unsigned char* target = NULL;
  int key_length = 0;
  int source_length = 0;
  int target_length = 0;
  int key_offset = 0;
  int source_offset = 0;
  int target_offset = 0;
  int key_size = 0;
  int source_size = 0;
  int target_size = 0;
  if (!arg_str(env, argv[0], algorithm, 32, E_ALGORITHM)) return NULL;
  const EVP_MD* evp_md = EVP_get_digestbyname(algorithm);
  if (!evp_md) THROW(env, E_ALGORITHM_UNKNOWN);
  int nid = EVP_MD_type(evp_md);
  assert(nid != NID_undef);
  target_size = EVP_MD_size(evp_md);
  assert(target_size > 0);
  if (
    !arg_buf(env, argv[1], &key, &key_length, E_KEY) ||
    !arg_int(env, argv[2], &key_offset, E_KEY_OFFSET) ||
    !arg_int(env, argv[3], &key_size, E_KEY_SIZE) ||
    !arg_buf(env, argv[4], &source, &source_length, E_SOURCE) ||
    !arg_int(env, argv[5], &source_offset, E_SOURCE_OFFSET) ||
    !arg_int(env, argv[6], &source_size, E_SOURCE_SIZE) ||
    !arg_buf(env, argv[7], &target, &target_length, E_TARGET) ||
    !arg_int(env, argv[8], &target_offset, E_TARGET_OFFSET) ||
    !range(env, key_offset, key_size, key_length, E_KEY_RANGE) ||
    !range(env, source_offset, source_size, source_length, E_SOURCE_RANGE) ||
    !range(env, target_offset, target_size, target_length, E_TARGET_RANGE)
  ) {
    return NULL;
  }
  key += key_offset;
  source += source_offset;
  target += target_offset;
  if (argc == 9) {
    const char* error = execute_hmac(
      nid,
      key,
      key_size,
      source,
      source_size,
      target
    );
    if (error) THROW(env, error);
    napi_value result;
    OK(napi_create_int64(env, target_size, &result));
    return result;
  }
  return task_create(
    env,            // env
    FLAG_HMAC,      // flags
    nid,            // nid
    0,              // encrypt
    key,            // key
    NULL,           // iv
    source,         // source
    target,         // target
    NULL,           // aad
    NULL,           // tag
    key_size,       // key_size
    0,              // iv_size
    source_size,    // source_size
    target_size,    // target_size
    0,              // aad_size
    0,              // tag_size
    argv[1],        // ref_key
    NULL,           // ref_iv
    argv[4],        // ref_source
    argv[7],        // ref_target
    NULL,           // ref_aad
    NULL,           // ref_tag
    argv[9]         // ref_callback
  );
}

static void key_finalize(napi_env env, void* key, void* hint) {
  EVP_PKEY_free(key);
  key = hint;
}

static napi_value key(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  OK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc != 1) THROW(env, E_ARGUMENTS);
  unsigned char* key = NULL;
  int key_length = 0;
  if (!arg_buf(env, argv[0], &key, &key_length, E_KEY)) {
    THROW(env, E_ARGUMENTS);
    return NULL;
  }
  BIO *keybio = BIO_new_mem_buf(key, key_length);
  if (keybio == NULL) {
    THROW(env, "key buffer allocation failed");
    return NULL;
  }
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
  if (pkey == NULL) {
    BIO_free(keybio);
    if (keybio == NULL) {
      THROW(env, "key buffer allocation failed");
      return NULL;
    }
    keybio = BIO_new_mem_buf(key, key_length);
    pkey = PEM_read_bio_PUBKEY(keybio, NULL, NULL, NULL);
  }
  BIO_free(keybio);
  if (pkey == NULL) {
    THROW(env, "invalid public/private key");
    return NULL;
  }
  napi_value external_key;
  OK(napi_create_external(env, pkey, key_finalize, NULL, &external_key));
  return external_key;
}

static napi_value signature(napi_env env, napi_callback_info info) {
  size_t argc = 9;
  napi_value argv[9];
  OK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc != 8 && argc != 9) THROW(env, E_ARGUMENTS);

  // arguments
  char algorithm[32];
  int sign = 0;
  void* key;
  unsigned char* source = NULL;
  int source_offset = 0;
  int source_size = 0;
  unsigned char* target = NULL;
  int target_offset = 0;

  int source_length = 0;
  int target_length = 0;
  int target_size = 0;

  if (!arg_str(env, argv[0], algorithm, 32, E_ALGORITHM)) return NULL;
  const EVP_MD* evp_md = EVP_get_digestbyname(algorithm);
  if (!evp_md) THROW(env, E_ALGORITHM_UNKNOWN);
  // We avoid EVP_CIPHER_type() since this returns `NID_undef` for some ciphers:
  int nid = EVP_MD_type(evp_md);
  assert(nid != NID_undef);

  if (!arg_int(env, argv[1], &sign, E_SIGN)) return NULL;
  if (sign != 0 && sign != 1) THROW(env, E_SIGN);

  if (napi_get_value_external(env, argv[2], &key)) {
    THROW(env, E_KEY_EXTERNAL);
    return NULL;
  }

  if (
    !arg_buf(env, argv[3], &source, &source_length, E_SOURCE) ||
    !arg_int(env, argv[4], &source_offset, E_SOURCE_OFFSET) ||
    !arg_int(env, argv[5], &source_size, E_SOURCE_SIZE) ||
    !arg_buf(env, argv[6], &target, &target_length, E_TARGET) ||
    !arg_int(env, argv[7], &target_offset, E_TARGET_OFFSET) ||
    !range(env, source_offset, source_size, source_length, E_SOURCE_RANGE)
  ) {
    return NULL;
  }
  EVP_PKEY *pkey = (EVP_PKEY*) key;
  target_size = EVP_PKEY_size(pkey);
  if (!range(env, target_offset, target_size, target_length, E_TARGET_RANGE)) return NULL;
  source += source_offset;
  target += target_offset;

  if (argc == 8) {
    const char* error = execute_signature(
      nid,
      sign,
      pkey,
      source,
      source_size,
      target,
      &target_size
    );
    if (error) THROW(env, error);
    napi_value result;
    OK(napi_create_int64(env, target_size, &result));
    return result;
  }
  return task_create(
    env,             // env
    FLAG_SIGNATURE,  // flags
    nid,             // nid
    sign,            // sign
    NULL,            // key
    NULL,            // iv
    source,          // source
    target,          // target
    NULL,            // aad
    NULL,            // tag
    0,               // key_size
    0,               // iv_size
    source_size,     // source_size
    target_size,     // target_size
    0,               // aad_size
    0,               // tag_size
    argv[2],         // ref_key
    NULL,            // ref_iv
    argv[3],         // ref_source
    argv[6],         // ref_target
    NULL,            // ref_aad
    NULL,            // ref_tag
    argv[8]          // ref_callback
  );
}

void export_error(
  napi_env env,
  napi_value exports,
  const char* code,
  const char* error
) {
  napi_value string;
  OK(napi_create_string_utf8(env, error, NAPI_AUTO_LENGTH, &string));
  OK(napi_set_named_property(env, exports, code, string));
}

static napi_value Init(napi_env env, napi_value exports) {
  // We require assert() for safety (our asserts are not side-effect free):
  #ifdef NDEBUG
    printf("NDEBUG compile flag not supported, assert() must not be a no-op\n");
    abort();
  #endif
  // Exports:
  napi_value fn_cipher;
  OK(napi_create_function(env, NULL, 0, cipher, NULL, &fn_cipher));
  OK(napi_set_named_property(env, exports, "cipher", fn_cipher));
  napi_value fn_hash;
  OK(napi_create_function(env, NULL, 0, hash, NULL, &fn_hash));
  OK(napi_set_named_property(env, exports, "hash", fn_hash));
  napi_value fn_hmac;
  OK(napi_create_function(env, NULL, 0, hmac, NULL, &fn_hmac));
  OK(napi_set_named_property(env, exports, "hmac", fn_hmac));
  napi_value fn_key;
  OK(napi_create_function(env, NULL, 0, key, NULL, &fn_key));
  OK(napi_set_named_property(env, exports, "key", fn_key));
  napi_value fn_signature;
  OK(napi_create_function(env, NULL, 0, signature, NULL, &fn_signature));
  OK(napi_set_named_property(env, exports, "signature", fn_signature));
  napi_value evp_max_block;
  OK(napi_create_int64(env, (int64_t) EVP_MAX_BLOCK_LENGTH, &evp_max_block));
  OK(napi_set_named_property(env, exports, "CIPHER_BLOCK_MAX", evp_max_block));
  // OpenSSL does not expose an EVP_MD_MAX_BLOCK_LENGTH equivalent for digests.
  export_error(env, exports, "E_AAD", E_AAD);
  export_error(env, exports, "E_AAD_INVALID", E_AAD_INVALID);
  export_error(env, exports, "E_AAD_OFFSET", E_AAD_OFFSET);
  export_error(env, exports, "E_AAD_RANGE", E_AAD_RANGE);
  export_error(env, exports, "E_AAD_SIZE", E_AAD_SIZE);
  export_error(env, exports, "E_ALGORITHM", E_ALGORITHM);
  export_error(env, exports, "E_ALGORITHM_DISABLED", E_ALGORITHM_DISABLED);
  export_error(env, exports, "E_ALGORITHM_UNKNOWN", E_ALGORITHM_UNKNOWN);
  export_error(env, exports, "E_ARGUMENTS", E_ARGUMENTS);
  export_error(env, exports, "E_BUFFER_LENGTH", E_BUFFER_LENGTH);
  export_error(env, exports, "E_CALLBACK", E_CALLBACK);
  export_error(env, exports, "E_CANCELLED", E_CANCELLED);
  export_error(env, exports, "E_CORRUPT", E_CORRUPT);
  export_error(env, exports, "E_ENCRYPT", E_ENCRYPT);
  export_error(env, exports, "E_IV", E_IV);
  export_error(env, exports, "E_IV_INVALID", E_IV_INVALID);
  export_error(env, exports, "E_IV_OFFSET", E_IV_OFFSET);
  export_error(env, exports, "E_IV_RANGE", E_IV_RANGE);
  export_error(env, exports, "E_IV_SIZE", E_IV_SIZE);
  export_error(env, exports, "E_KEY", E_KEY);
  export_error(env, exports, "E_KEY_EXTERNAL", E_KEY_EXTERNAL);
  export_error(env, exports, "E_KEY_INVALID", E_KEY_INVALID);
  export_error(env, exports, "E_KEY_OFFSET", E_KEY_OFFSET);
  export_error(env, exports, "E_KEY_RANGE", E_KEY_RANGE);
  export_error(env, exports, "E_KEY_SIZE", E_KEY_SIZE);
  export_error(env, exports, "E_OOM", E_OOM);
  export_error(env, exports, "E_SOURCE", E_SOURCE);
  export_error(env, exports, "E_SOURCE_OFFSET", E_SOURCE_OFFSET);
  export_error(env, exports, "E_SOURCE_RANGE", E_SOURCE_RANGE);
  export_error(env, exports, "E_SOURCE_SIZE", E_SOURCE_SIZE);
  export_error(env, exports, "E_TAG", E_TAG);
  export_error(env, exports, "E_TAG_INVALID", E_TAG_INVALID);
  export_error(env, exports, "E_TAG_OFFSET", E_TAG_OFFSET);
  export_error(env, exports, "E_TAG_RANGE", E_TAG_RANGE);
  export_error(env, exports, "E_TAG_SIZE", E_TAG_SIZE);
  export_error(env, exports, "E_TARGET", E_TARGET);
  export_error(env, exports, "E_TARGET_OFFSET", E_TARGET_OFFSET);
  export_error(env, exports, "E_TARGET_RANGE", E_TARGET_RANGE);
  export_error(env, exports, "E_SIGN", E_SIGN);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)

// S.D.G.

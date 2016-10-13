#include <nan.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

class CipherWorker : public Nan::AsyncWorker {
 public:
  CipherWorker(
   const EVP_CIPHER* cipher,
   const unsigned int encrypt,
   v8::Local<v8::Object> &keyHandle,
   const size_t keyOffset,
   v8::Local<v8::Object> &ivHandle,
   const size_t ivOffset,
   v8::Local<v8::Object> &sourceHandle,
   const size_t sourceOffset,
   const size_t sourceSize,
   v8::Local<v8::Object> &targetHandle,
   const size_t targetOffset,
   Nan::Callback *end
  ) : Nan::AsyncWorker(end),
     cipher(cipher),
     encrypt(encrypt),
     keyOffset(keyOffset),
     ivOffset(ivOffset),
     sourceOffset(sourceOffset),
     sourceSize(sourceSize),
     targetOffset(targetOffset) {
       SaveToPersistent("keyHandle", keyHandle);
       SaveToPersistent("ivHandle", ivHandle);
       SaveToPersistent("sourceHandle", sourceHandle);
       SaveToPersistent("targetHandle", targetHandle);
       key = reinterpret_cast<const unsigned char*>(node::Buffer::Data(keyHandle));
       iv = reinterpret_cast<const unsigned char*>(node::Buffer::Data(ivHandle));
       source = reinterpret_cast<const unsigned char*>(node::Buffer::Data(sourceHandle));
       target = reinterpret_cast<unsigned char*>(node::Buffer::Data(targetHandle));
       targetSize = 0;
  }

  ~CipherWorker() {}

  void Execute() {
    int written;
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    if (!EVP_CipherInit_ex(
      &ctx,
      cipher,
      nullptr,
      key + keyOffset,
      iv + ivOffset,
      encrypt
    )) {
      EVP_CIPHER_CTX_cleanup(&ctx);
      SetErrorMessage("cipher init error");
      return;
    }
    if (!EVP_CipherUpdate(
      &ctx,
      target + targetOffset,
      &written,
      source + sourceOffset,
      sourceSize
    )) {
      EVP_CIPHER_CTX_cleanup(&ctx);
      SetErrorMessage("cipher update error");
      return;
    }
    targetSize += written;
    if (!EVP_CipherFinal_ex(
      &ctx,
      target + (targetOffset + written),
      &written
    )) {
      EVP_CIPHER_CTX_cleanup(&ctx);
      SetErrorMessage("cipher final error");
      return;
    }
    targetSize += written;
    EVP_CIPHER_CTX_cleanup(&ctx);
  }

  void HandleOKCallback () {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
      Nan::Undefined(),
      Nan::New<v8::Number>(targetSize)
    };
    callback->Call(2, argv);
  }

 private:
  const EVP_CIPHER* cipher;
  const unsigned int encrypt;
  const size_t keyOffset;
  const size_t ivOffset;
  const size_t sourceOffset;
  const size_t sourceSize;
  const size_t targetOffset;
  const unsigned char* key;
  const unsigned char* iv;
  const unsigned char* source;
  unsigned char* target;
  size_t targetSize;
};

class HashWorker : public Nan::AsyncWorker {
 public:
  HashWorker(
    const EVP_MD* digest,
    v8::Local<v8::Object> &sourceHandle,
    const size_t sourceOffset,
    const size_t sourceSize,
    v8::Local<v8::Object> &targetHandle,
    const size_t targetOffset,
    Nan::Callback *end
  ) : Nan::AsyncWorker(end),
      digest(digest),
      sourceOffset(sourceOffset),
      sourceSize(sourceSize),
      targetOffset(targetOffset) {
        SaveToPersistent("sourceHandle", sourceHandle);
        SaveToPersistent("targetHandle", targetHandle);
        source = reinterpret_cast<const unsigned char*>(node::Buffer::Data(sourceHandle));
        target = reinterpret_cast<unsigned char*>(node::Buffer::Data(targetHandle));
  }

  ~HashWorker() {}

  void Execute() {
    EVP_MD_CTX ctx;
    EVP_MD_CTX_init(&ctx);
    if (!EVP_DigestInit_ex(&ctx, digest, nullptr)) {
      EVP_MD_CTX_cleanup(&ctx);
      SetErrorMessage("digest init error");
      return;
    }
    if (!EVP_DigestUpdate(&ctx, source + sourceOffset, sourceSize)) {
      EVP_MD_CTX_cleanup(&ctx);
      SetErrorMessage("digest update error");
      return;
    }
    if (!EVP_DigestFinal_ex(&ctx, target + targetOffset, nullptr)) {
      EVP_MD_CTX_cleanup(&ctx);
      SetErrorMessage("digest final error");
      return;
    }
    EVP_MD_CTX_cleanup(&ctx);
  }

 private:
  const EVP_MD* digest;
  const size_t sourceOffset;
  const size_t sourceSize;
  const size_t targetOffset;
  const unsigned char* source;
  unsigned char* target;
};

class HMACWorker : public Nan::AsyncWorker {
 public:
  HMACWorker(
    const EVP_MD* digest,
    v8::Local<v8::Object> &keyHandle,
    const size_t keyOffset,
    const size_t keySize,
    v8::Local<v8::Object> &sourceHandle,
    const size_t sourceOffset,
    const size_t sourceSize,
    v8::Local<v8::Object> &targetHandle,
    const size_t targetOffset,
    Nan::Callback *end
  ) : Nan::AsyncWorker(end),
      digest(digest),
      keyOffset(keyOffset),
      keySize(keySize),
      sourceOffset(sourceOffset),
      sourceSize(sourceSize),
      targetOffset(targetOffset) {
        SaveToPersistent("keyHandle", keyHandle);
        SaveToPersistent("sourceHandle", sourceHandle);
        SaveToPersistent("targetHandle", targetHandle);
        key = reinterpret_cast<const unsigned char*>(node::Buffer::Data(keyHandle));
        source = reinterpret_cast<const unsigned char*>(node::Buffer::Data(sourceHandle));
        target = reinterpret_cast<unsigned char*>(node::Buffer::Data(targetHandle));
  }

  ~HMACWorker() {}

  void Execute () {
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    if (keySize == 0) {
      if (!HMAC_Init_ex(&ctx, "", 0, digest, nullptr)) {
        HMAC_CTX_cleanup(&ctx);
        SetErrorMessage("hmac init error with zero-size key");
        return;
      }
    } else {
      if (!HMAC_Init_ex(&ctx, key + keyOffset, keySize, digest, nullptr)) {
        HMAC_CTX_cleanup(&ctx);
        SetErrorMessage("hmac init error");
        return;
      }
    }
    if (!HMAC_Update(&ctx, source + sourceOffset, sourceSize)) {
      HMAC_CTX_cleanup(&ctx);
      SetErrorMessage("hmac update error");
      return;
    }
    if (!HMAC_Final(&ctx, target + targetOffset, nullptr)) {
      HMAC_CTX_cleanup(&ctx);
      SetErrorMessage("hmac final error");
      return;
    }
    HMAC_CTX_cleanup(&ctx);
  }

 private:
  const EVP_MD* digest;
  const size_t keyOffset;
  const size_t keySize;
  const size_t sourceOffset;
  const size_t sourceSize;
  const size_t targetOffset;
  const unsigned char* key;
  const unsigned char* source;
  unsigned char* target;
};

size_t cipher_block_size(
  const EVP_CIPHER* cipher,
  const unsigned int encrypt,
  const size_t sourceSize
) {
  size_t blockSize = EVP_CIPHER_block_size(cipher);
  if (encrypt) {
    // The amount of data written depends on the block alignment of the
    // encrypted data: as a result the amount of data written may be anything
    // from zero bytes to (inl + cipher_block_size - 1) so outl should contain
    // sufficient room.
    return sourceSize + blockSize - 1;
  } else {
    // The parameters and restrictions are identical to the encryption
    // operations except that if padding is enabled the decrypted data buffer
    // out passed to EVP_DecryptUpdate() should have sufficient room for
    // (inl + cipher_block_size) bytes unless the cipher block size is 1 in
    // which case inl bytes is sufficient.
    return blockSize == 1 ? sourceSize : sourceSize + blockSize;
  }
};

NAN_METHOD(cipher) {
  if (
    info.Length() != 14 ||
    !info[0]->IsString() ||
    !info[1]->IsUint32() ||
    !node::Buffer::HasInstance(info[2]) ||
    !info[3]->IsUint32() ||
    !info[4]->IsUint32() ||
    !node::Buffer::HasInstance(info[5]) ||
    !info[6]->IsUint32() ||
    !info[7]->IsUint32() ||
    !node::Buffer::HasInstance(info[8]) ||
    !info[9]->IsUint32() ||
    !info[10]->IsUint32() ||
    !node::Buffer::HasInstance(info[11]) ||
    !info[12]->IsUint32() ||
    !info[13]->IsFunction()
  ) {
    return Nan::ThrowError(
      "bad arguments, expected: (string algorithm, int encrypt, "
      "Buffer key, int keyOffset, int keySize, "
      "Buffer iv, int ivOffset, int ivSize, "
      "Buffer source, int sourceOffset, int sourceSize, "
      "Buffer target, int targetOffset, function end)"
    );
  }
  Nan::Utf8String algorithm(info[0]);
  const EVP_CIPHER* cipher = EVP_get_cipherbyname(*algorithm);
  const unsigned int encrypt = info[1]->Uint32Value();
  v8::Local<v8::Object> keyHandle = info[2].As<v8::Object>();
  const size_t keyOffset = info[3]->Uint32Value();
  const int keySize = info[4]->Uint32Value();
  v8::Local<v8::Object> ivHandle = info[5].As<v8::Object>();
  const size_t ivOffset = info[6]->Uint32Value();
  const int ivSize = info[7]->Uint32Value();
  v8::Local<v8::Object> sourceHandle = info[8].As<v8::Object>();
  const size_t sourceOffset = info[9]->Uint32Value();
  const size_t sourceSize = info[10]->Uint32Value();
  v8::Local<v8::Object> targetHandle = info[11].As<v8::Object>();
  const size_t targetOffset = info[12]->Uint32Value();
  Nan::Callback *end = new Nan::Callback(info[13].As<v8::Function>());
  if (!cipher) {
    return Nan::ThrowError("algorithm not supported");
  }
  if (encrypt != 0 && encrypt != 1) {
    return Nan::ThrowError("encrypt must be 0 or 1");
  }
  if (keySize != EVP_CIPHER_key_length(cipher)) {
    return Nan::ThrowError("invalid key size");
  }
  if (keyOffset + keySize > node::Buffer::Length(keyHandle)) {
    return Nan::ThrowError("key would overflow");
  }
  if (ivSize != EVP_CIPHER_iv_length(cipher)) {
    return Nan::ThrowError("invalid iv size");
  }
  if (ivOffset + ivSize > node::Buffer::Length(ivHandle)) {
    return Nan::ThrowError("iv would overflow");
  }
  if (sourceOffset + sourceSize > node::Buffer::Length(sourceHandle)) {
    return Nan::ThrowError("source would overflow");
  }
  const size_t targetSize = cipher_block_size(cipher, encrypt, sourceSize);
  if (targetOffset + targetSize > node::Buffer::Length(targetHandle)) {
    return Nan::ThrowError("target too small");
  }
  Nan::AsyncQueueWorker(new CipherWorker(
    cipher,
    encrypt,
    keyHandle,
    keyOffset,
    ivHandle,
    ivOffset,
    sourceHandle,
    sourceOffset,
    sourceSize,
    targetHandle,
    targetOffset,
    end
  ));
}

NAN_METHOD(hash) {
  if (
    info.Length() != 7 ||
    !info[0]->IsString() ||
    !node::Buffer::HasInstance(info[1]) ||
    !info[2]->IsUint32() ||
    !info[3]->IsUint32() ||
    !node::Buffer::HasInstance(info[4]) ||
    !info[5]->IsUint32() ||
    !info[6]->IsFunction()
  ) {
    return Nan::ThrowError(
      "bad arguments, expected: (string algorithm, "
      "Buffer source, int sourceOffset, int sourceSize, "
      "Buffer target, int targetOffset, function end)"
    );
  }
  Nan::Utf8String algorithm(info[0]);
  const EVP_MD* digest = EVP_get_digestbyname(*algorithm);
  if (!digest) {
    return Nan::ThrowError("algorithm not supported");
  }
  v8::Local<v8::Object> sourceHandle = info[1].As<v8::Object>();
  const size_t sourceOffset = info[2]->Uint32Value();
  const size_t sourceSize = info[3]->Uint32Value();
  v8::Local<v8::Object> targetHandle = info[4].As<v8::Object>();
  const size_t targetOffset = info[5]->Uint32Value();
  Nan::Callback *end = new Nan::Callback(info[6].As<v8::Function>());
  if (sourceOffset + sourceSize > node::Buffer::Length(sourceHandle)) {
    return Nan::ThrowError("source would overflow");
  }
  if (targetOffset + EVP_MD_size(digest) > node::Buffer::Length(targetHandle)) {
    return Nan::ThrowError("target too small");
  }
  Nan::AsyncQueueWorker(new HashWorker(
    digest,
    sourceHandle,
    sourceOffset,
    sourceSize,
    targetHandle,
    targetOffset,
    end
  ));
}

NAN_METHOD(hmac) {
  if (
    info.Length() != 10 ||
    !info[0]->IsString() ||
    !node::Buffer::HasInstance(info[1]) ||
    !info[2]->IsUint32() ||
    !info[3]->IsUint32() ||
    !node::Buffer::HasInstance(info[4]) ||
    !info[5]->IsUint32() ||
    !info[6]->IsUint32() ||
    !node::Buffer::HasInstance(info[7]) ||
    !info[8]->IsUint32() ||
    !info[9]->IsFunction()
  ) {
    return Nan::ThrowError(
      "bad arguments, expected: (string algorithm, "
      "Buffer key, int keyOffset, int keySize, "
      "Buffer source, int sourceOffset, int sourceSize, "
      "Buffer target, int targetOffset, function end)"
    );
  }
  Nan::Utf8String algorithm(info[0]);
  const EVP_MD* digest = EVP_get_digestbyname(*algorithm);
  if (!digest) {
    return Nan::ThrowError("algorithm not supported");
  }
  v8::Local<v8::Object> keyHandle = info[1].As<v8::Object>();
  const size_t keyOffset = info[2]->Uint32Value();
  const size_t keySize = info[3]->Uint32Value();
  v8::Local<v8::Object> sourceHandle = info[4].As<v8::Object>();
  const size_t sourceOffset = info[5]->Uint32Value();
  const size_t sourceSize = info[6]->Uint32Value();
  v8::Local<v8::Object> targetHandle = info[7].As<v8::Object>();
  const size_t targetOffset = info[8]->Uint32Value();
  Nan::Callback *end = new Nan::Callback(info[9].As<v8::Function>());
  if (keyOffset + keySize > node::Buffer::Length(keyHandle)) {
    return Nan::ThrowError("key would overflow");
  }
  if (sourceOffset + sourceSize > node::Buffer::Length(sourceHandle)) {
    return Nan::ThrowError("source would overflow");
  }
  if (targetOffset + EVP_MD_size(digest) > node::Buffer::Length(targetHandle)) {
    return Nan::ThrowError("target too small");
  }
  Nan::AsyncQueueWorker(new HMACWorker(
    digest,
    keyHandle,
    keyOffset,
    keySize,
    sourceHandle,
    sourceOffset,
    sourceSize,
    targetHandle,
    targetOffset,
    end
  ));
}

NAN_MODULE_INIT(Init) {
  OpenSSL_add_all_algorithms();
  NAN_EXPORT(target, cipher);
  NAN_EXPORT(target, hash);
  NAN_EXPORT(target, hmac);
}

NODE_MODULE(binding, Init);

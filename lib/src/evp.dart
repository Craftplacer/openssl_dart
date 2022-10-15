import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:meta/meta.dart';
import 'bindings.g.dart' show evp_md_ctx_st, evp_md_st, evp_pkey_st;
import 'err.dart';
import 'lib.dart';
import 'rsa.dart';
import 'utils.dart';

typedef DigestContextHandle = Pointer<evp_md_ctx_st>;
typedef DigestAlgorithmHandle = Pointer<evp_md_st>;
typedef PKeyHandle = Pointer<evp_pkey_st>;

class DigestContext {
  DigestContextHandle? _handle;

  DigestContext() {
    final handle = nativeLibrary.EVP_MD_CTX_new();
    if (handle == nullptr) throw OpenSSLException();
    _handle = handle;
  }

  void dispose() {
    nativeLibrary.EVP_MD_CTX_free(_handle!);
    _handle = null;
  }

  void digestSignInit(DigestAlgorithm algorithm, PKey privateKey) {
    nativeLibrary.EVP_DigestSignInit(
      _handle!,
      nullptr,
      algorithm.handle,
      nullptr,
      privateKey.handle,
    ).throwIfNotOne();
  }

  void digestUpdate(Uint8List data) {
    // FIXME(Craftplacer): Potential native memory leak
    final dataPointer = data.allocate<Void>();
    nativeLibrary.EVP_DigestUpdate(
      _handle!,
      dataPointer,
      data.length,
    ).throwIfNotOne();
  }

  Uint8List digestSignFinal() {
    Pointer<Int>? hSiglen;
    Pointer<UnsignedChar>? hSig;
    try {
      // If sig is NULL then the maximum size of the output buffer is written to
      // the siglen parameter.
      hSiglen = malloc.call<Int>();
      nativeLibrary.EVP_DigestSignFinal(
        _handle!,
        nullptr,
        hSiglen,
      ).throwIfNotOne();
      final siglen = hSiglen.value;

      hSig = malloc.call<UnsignedChar>(siglen);
      nativeLibrary.EVP_DigestSignFinal(
        _handle!,
        hSig,
        hSiglen,
      ).throwIfNotOne();

      return hSig.toUint8List(siglen);
    } finally {
      if (hSig != null) malloc.free(hSig);
      if (hSiglen != null) malloc.free(hSiglen);
    }
  }

  void digestVerifyInit(DigestAlgorithm algorithm, PKey publicKey) {
    nativeLibrary.EVP_DigestVerifyInit(
      _handle!,
      nullptr,
      algorithm.handle,
      nullptr,
      publicKey.handle,
    ).throwIfNotOne();
  }

  VerifyResult digestVerifyFinal(Uint8List signature) {
    Pointer<UnsignedChar>? hSig;
    try {
      hSig = signature.allocate<UnsignedChar>();
      final result = nativeLibrary.EVP_DigestVerifyFinal(
        _handle!,
        hSig,
        signature.length,
      );

      // We don't throw, unless something has gone wrong with the verify process
      // itself, in which, OpenSSL should return a code lower than 0.
      switch (result) {
        case 0:
          final code = nativeLibrary.ERR_get_error();
          return VerifyResult(code);
        case 1:
          return VerifyResult.successful();
        default:
          throw OpenSSLException();
      }
    } finally {
      if (hSig != null) malloc.free(hSig);
    }
  }
}

class VerifyResult {
  final int code;

  bool get isSuccessful => code == 1;

  const VerifyResult(this.code);
  const VerifyResult.successful() : code = 1;

  /// Throws an exception with more details, if the result wasn't successful.
  void throwException() {
    if (isSuccessful) return;
    throw OpenSSLException.fromCode(code);
  }
}

enum DigestAlgorithm {
  md5,
  sha1,
  sha224,
  sha256,
  sha384,
  sha512,
  mdc2,
  ripemd160;

  DigestAlgorithmHandle get handle {
    switch (this) {
      case DigestAlgorithm.md5:
        return nativeLibrary.EVP_md5();
      case DigestAlgorithm.sha1:
        return nativeLibrary.EVP_sha1();
      case DigestAlgorithm.sha224:
        return nativeLibrary.EVP_sha224();
      case DigestAlgorithm.sha256:
        return nativeLibrary.EVP_sha256();
      case DigestAlgorithm.sha384:
        return nativeLibrary.EVP_sha384();
      case DigestAlgorithm.sha512:
        return nativeLibrary.EVP_sha512();
      case DigestAlgorithm.mdc2:
        return nativeLibrary.EVP_mdc2();
      case DigestAlgorithm.ripemd160:
        return nativeLibrary.EVP_ripemd160();
    }
  }
}

class PKey {
  static const _rsa = 6;

  PKeyHandle? _handle;

  @internal
  PKeyHandle get handle => _handle!;

  PKey() {
    final result = nativeLibrary.EVP_PKEY_new();
    if (result == nullptr) throw OpenSSLException();
    _handle = result;
  }

  void dispose() {
    nativeLibrary.EVP_PKEY_free(_handle!);
    _handle = null;
  }

  void assignRSA(RSA rsa) {
    final result = nativeLibrary.EVP_PKEY_assign(
      _handle!,
      _rsa,
      rsa.handle.cast<Void>(),
    );

    if (result == 0) throw OpenSSLException();
  }
}

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart' show hmac_ctx_st;
import 'err.dart';
import 'evp.dart' show DigestAlgorithm, DigestAlgorithmHandle;
import 'lib.dart';
import 'utils.dart';

typedef HMACContextHandle = Pointer<hmac_ctx_st>;

// TODO(Craftplacer): implement HMAC(...)

class HMACContext {
  HMACContextHandle? _handle;

  int get size {
    final result = nativeLibrary.HMAC_size(_handle!);
    if (result == 0) throw OpenSSLException();
    return result;
  }

  DigestAlgorithmHandle? get md {
    final result = nativeLibrary.HMAC_CTX_get_md(_handle!);
    return result == nullptr ? null : result;
  }

  set flags(int flags) => nativeLibrary.HMAC_CTX_set_flags(_handle!, flags);

  HMACContext() {
    final result = nativeLibrary.HMAC_CTX_new();
    if (result == nullptr) throw OpenSSLException();
    _handle = result;
  }

  void dispose() {
    nativeLibrary.HMAC_CTX_free(_handle!);
    _handle = null;
  }

  void init(Uint8List key, DigestAlgorithm algorithm) {
    Pointer<Void>? hKey;
    try {
      hKey = key.allocate();
      nativeLibrary.HMAC_Init_ex(
        _handle!,
        hKey,
        key.length,
        algorithm.handle,
        nullptr,
      ).throwIfNotOne();
    } finally {
      if (hKey != null) malloc.free(hKey);
    }
  }

  void update(Uint8List data) {
    Pointer<UnsignedChar>? hData;
    try {
      hData = data.allocate();
      nativeLibrary.HMAC_Update(
        _handle!,
        hData,
        data.length,
      ).throwIfNotOne();
    } finally {
      if (hData != null) malloc.free(hData);
    }
  }

  @Deprecated("Unimplemented")
  Uint8List finalize() {
    throw UnimplementedError();

    // ignore: dead_code
    Pointer<UnsignedChar>? hMd;
    Pointer<UnsignedInt>? hLen;
    try {
      const length = 256;

      hMd = malloc.call<UnsignedChar>(length);
      hLen = malloc.call<UnsignedInt>()..value = length;
      nativeLibrary.HMAC_Final(
        _handle!,
        hMd,
        hLen,
      ).throwIfNotOne();
    } finally {
      if (hLen != null) malloc.free(hLen);
      if (hMd != null) malloc.free(hMd);
    }
  }

  void reset() => nativeLibrary.HMAC_CTX_reset(_handle!).throwIfNotOne();

  void copy(HMACContext destinationContext) {
    nativeLibrary.HMAC_CTX_copy(
      destinationContext._handle!,
      _handle!,
    ).throwIfNotOne();
  }
}

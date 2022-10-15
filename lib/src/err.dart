import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'lib.dart';

class OpenSSLException implements Exception {
  final int code;

  String get message {
    const length = 256;
    Pointer<Char>? hBuf;
    try {
      hBuf = malloc.call<Char>(length);
      nativeLibrary.ERR_error_string_n(code, hBuf, length);
      return hBuf.cast<Utf8>().toDartString();
    } finally {
      if (hBuf != null) malloc.free(hBuf);
    }
  }

  String get library {
    return nativeLibrary.ERR_lib_error_string(code) //
        .cast<Utf8>()
        .toDartString();
  }

  String get function {
    return nativeLibrary.ERR_func_error_string(code)
        .cast<Utf8>()
        .toDartString();
  }

  String get reason {
    return nativeLibrary.ERR_reason_error_string(code)
        .cast<Utf8>()
        .toDartString();
  }

  /// Creates an [OpenSSLException] from the given error code.
  const OpenSSLException.fromCode(this.code);

  /// Creates an [OpenSSLException] from the current error queue.
  factory OpenSSLException() {
    final code = nativeLibrary.ERR_get_error();
    return OpenSSLException.fromCode(code);
  }

  @override
  String toString() => "OpenSSLException($message)";
}

extension IntExtensions on int {
  void throwIfNotOne() {
    if (this != 1) throw OpenSSLException.fromCode(this);
  }
}

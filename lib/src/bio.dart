import 'dart:developer';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:meta/meta.dart';
import 'bindings.g.dart' show bio_method_st, bio_st;
import 'err.dart';
import 'lib.dart' show nativeLibrary;
import 'utils.dart';

typedef BioHandle = Pointer<bio_st>;
typedef BioMethodHandle = Pointer<bio_method_st>;

class BIO {
  BioHandle? _handle;
  Pointer<Void>? _hBuf;

  @internal
  BioHandle get handle => _handle!;

  int get numberWritten {
    final result = nativeLibrary.BIO_number_written(_handle!);
    if (result == -1) throw OpenSSLException();
    return result;
  }

  int get numberRead {
    final result = nativeLibrary.BIO_number_read(_handle!);
    if (result == -1) throw OpenSSLException();
    return result;
  }

  BIO(BIOMethod method) {
    final hMethod = method.instantiate();
    final result = nativeLibrary.BIO_new(hMethod);
    if (result == nullptr) throw OpenSSLException();
    _handle = result;
  }

  BIO.memory(Uint8List data) {
    try {
      _hBuf = data.allocate<Void>();
      final result = nativeLibrary.BIO_new_mem_buf(_hBuf!, data.length);
      if (result == nullptr) throw OpenSSLException();
      _handle = result;
    } catch (e, s) {
      if (_hBuf != null) {
        malloc.free(_hBuf!);
        log(
          "freeing buffer after error",
          error: e,
          stackTrace: s,
          name: "BIO.memory",
        );
      }
      rethrow;
    }
  }

  void dispose() {
    if (_hBuf != null) {
      malloc.free(_hBuf!);
      _hBuf = null;
    }

    nativeLibrary.BIO_free(_handle!);
    _handle = null;
  }

  /// [write] attempts to write [data] to the BIO.
  int write(Uint8List data) {
    Pointer<Void>? hData;
    try {
      hData = data.allocate();

      final result = nativeLibrary.BIO_write(
        _handle!,
        hData,
        data.length,
      );

      // If the return value is -2 then the operation is not implemented in the
      // specific BIO type.
      if (result == -2) throw UnimplementedError();

      return result;
    } finally {
      if (hData != null) malloc.free(hData);
    }
  }

  /// [puts] attempts to write a string [buf] to the BIO.
  int puts(String buf) {
    final result = nativeLibrary.BIO_puts(
      _handle!,
      buf.toNativeUtf8().cast(),
    )..throwIfNotOne();

    // If the return value is -2 then the operation is not implemented in the
    // specific BIO type.
    if (result == -2) throw UnimplementedError();

    return result;
  }

  /// [read] attempts to read [length] bytes from the BIO.
  Uint8List read(int length) {
    Pointer<Uint8>? buf;

    try {
      buf = malloc.call<Uint8>(length);
      final result = nativeLibrary.BIO_read(
        _handle!,
        buf.cast(),
        length,
      );

      // If the return value is -2 then the operation is not implemented in the
      // specific BIO type.
      if (result == -2) throw UnimplementedError();

      // ... no data was successfully read or written if the result is 0 or -1.
      if (result == 0 || result == -1) return Uint8List(0);

      return buf.toUint8List(result);
    } finally {
      if (buf != null) malloc.free(buf);
    }
  }

  /// [gets] performs the BIOs "gets" operation.
  ///
  /// Usually this operation will attempt to read a line of data from the BIO of
  /// maximum length size-1. There are exceptions to this, however; for example,
  /// [gets] on a digest BIO will calculate and return the digest and other
  /// BIOs may not support [gets] at all.
  String gets(int length) {
    final buf = malloc.call<Char>(length);
    final result = nativeLibrary.BIO_gets(
      _handle!,
      buf,
      length,
    )..throwIfNotOne();

    // If the return value is -2 then the operation is not implemented in the
    // specific BIO type.
    if (result == -2) throw UnimplementedError();

    // HACK(Craftplacer): Untested
    return buf.cast<Utf8>().toDartString();
  }
}

enum BIOMethod {
  fBase64,
  sMem;

  @internal
  BioMethodHandle Function() get instantiate {
    switch (this) {
      case BIOMethod.fBase64:
        return nativeLibrary.BIO_f_base64;
      case BIOMethod.sMem:
        return nativeLibrary.BIO_s_mem;
    }
  }
}

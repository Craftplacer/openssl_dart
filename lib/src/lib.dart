import 'dart:ffi';
import 'package:meta/meta.dart';
import 'bindings.g.dart';

final _dynamicLibrary = DynamicLibrary.open("libcrypto.so");

@internal
final nativeLibrary = NativeLibrary(_dynamicLibrary);

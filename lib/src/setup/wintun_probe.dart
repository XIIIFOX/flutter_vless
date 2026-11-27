import 'dart:ffi';
import 'dart:io';

typedef _CreateAdapter = Pointer<Void> Function(
  Pointer<Uint16>,
  Pointer<Uint16>,
  Pointer<Void>,
);

/// Internal child process for the verified, private Wintun copy.
void main(List<String> args) {
  exitCode = 1;
  if (Abi.current() != Abi.windowsX64 || args.length != 2) return;
  final [dll, name] = args;
  final systemRoot = Platform.environment['SystemRoot'];
  if (systemRoot == null ||
      !RegExp(r'^FlutterVlessSetup-[0-9a-f]{32}$').hasMatch(name) ||
      dll.toLowerCase() !=
          '$systemRoot\\Temp\\$name\\wintun.dll'.toLowerCase()) {
    return;
  }
  try {
    if (_stage(dll, name)) exitCode = 0;
  } on Exception {
    // The calling setup reports a bounded stage error.
  }
}

bool _stage(String dll, String name) {
  final kernel = DynamicLibrary.open('kernel32.dll');
  final localAlloc = kernel.lookupFunction<
      Pointer<Void> Function(Uint32, UintPtr),
      Pointer<Void> Function(int, int)>('LocalAlloc');
  final localFree = kernel.lookupFunction<Pointer<Void> Function(Pointer<Void>),
      Pointer<Void> Function(Pointer<Void>)>('LocalFree');
  final load = kernel.lookupFunction<
      Pointer<Void> Function(Pointer<Uint16>, Pointer<Void>, Uint32),
      Pointer<Void> Function(
          Pointer<Uint16>, Pointer<Void>, int)>('LoadLibraryExW');
  final getExport = kernel.lookupFunction<
      Pointer<Void> Function(Pointer<Void>, Pointer<Uint8>),
      Pointer<Void> Function(Pointer<Void>, Pointer<Uint8>)>('GetProcAddress');
  final buffers = <Pointer<Void>>[];

  Pointer<Void> allocate(int bytes) {
    const fixedZeroedMemory = 0x40; // LPTR, including the string terminator.
    final buffer = localAlloc(fixedZeroedMemory, bytes);
    if (buffer == nullptr) throw const OSError('Cannot allocate native string');
    buffers.add(buffer);
    return buffer;
  }

  Pointer<Uint16> wide(String value) {
    final result =
        allocate((value.length + 1) * sizeOf<Uint16>()).cast<Uint16>();
    result.asTypedList(value.length).setAll(0, value.codeUnits);
    return result;
  }

  Pointer<Void> symbol(Pointer<Void> module, String value) {
    final result = allocate(value.length + 1).cast<Uint8>();
    result.asTypedList(value.length).setAll(0, value.codeUnits);
    return getExport(module, result);
  }

  try {
    const loadLibrarySearchSystem32 = 0x800;
    final module = load(wide(dll), nullptr, loadLibrarySearchSystem32);
    if (module == nullptr) return false;
    final create = symbol(module, 'WintunCreateAdapter');
    final close = symbol(module, 'WintunCloseAdapter');
    if (create == nullptr || close == nullptr) return false;
    final adapterName = wide(name);
    final adapter = create
        .cast<NativeFunction<_CreateAdapter>>()
        .asFunction<_CreateAdapter>()(adapterName, adapterName, nullptr);
    if (adapter == nullptr) return false;
    close
        .cast<NativeFunction<Void Function(Pointer<Void>)>>()
        .asFunction<void Function(Pointer<Void>)>()(adapter);
    // Wintun can queue native work during close. Keep the module loaded until
    // the child exits; the parent then removes the private files.
    return true;
  } finally {
    for (final buffer in buffers) {
      localFree(buffer);
    }
  }
}

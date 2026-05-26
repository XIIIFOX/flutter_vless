import 'dart:convert';
import 'dart:io';

const _hostName = 'dev.tfox.flutter_vless';

Future<void> main(List<String> args) async {
  final repo = _repoRoot();
  final options = _SetupOptions.parse(args);
  final extensionDir = Directory('${repo.path}/extensions/browser/chrome');
  final extensionManifest = File('${extensionDir.path}/manifest.json');
  final nativeHostDir =
      Directory('${repo.path}/native_hosts/flutter_vless_native_host');

  final extensionId =
      options.extensionId ?? _extensionIdFromManifest(extensionManifest);
  if (!options.skipBuild) {
    await _run('dart', ['pub', 'get'], workingDirectory: nativeHostDir.path);
    await Directory('${nativeHostDir.path}/build').create(recursive: true);
    await _run(
      'dart',
      [
        'compile',
        'exe',
        'bin/flutter_vless_native_host.dart',
        '-o',
        _nativeHostExecutable(nativeHostDir).path,
      ],
      workingDirectory: nativeHostDir.path,
    );
  }

  final executable = _nativeHostExecutable(nativeHostDir);
  if (!await executable.exists()) {
    throw StateError(
        'Native host executable does not exist: ${executable.path}');
  }

  final generatedManifest = File(
    '${nativeHostDir.path}/build/$_hostName.chrome.json',
  );
  await generatedManifest.writeAsString(
    const JsonEncoder.withIndent('  ').convert({
      'name': _hostName,
      'description': 'Flutter Vless Native Messaging Host',
      'path': executable.absolute.path,
      'type': 'stdio',
      'allowed_origins': ['chrome-extension://$extensionId/'],
    }),
  );

  final installedManifest = await _installManifest(
    generatedManifest,
    options.browser,
  );

  stdout.writeln('Chrome extension dev setup complete.');
  stdout.writeln('Extension ID: $extensionId');
  stdout.writeln('Extension path: ${extensionDir.absolute.path}');
  stdout.writeln('Native host executable: ${executable.absolute.path}');
  stdout.writeln('Native manifest: ${installedManifest.absolute.path}');
  stdout.writeln('');
  stdout.writeln(
      'Next: open chrome://extensions and load the extension path above.');
}

Directory _repoRoot() {
  final script = File(Platform.script.toFilePath());
  return script.parent.parent;
}

File _nativeHostExecutable(Directory nativeHostDir) {
  final suffix = Platform.isWindows ? '.exe' : '';
  return File('${nativeHostDir.path}/build/flutter_vless_native_host$suffix');
}

Future<void> _run(
  String executable,
  List<String> arguments, {
  required String workingDirectory,
}) async {
  stdout.writeln('> $executable ${arguments.join(' ')}');
  final result = await Process.run(
    executable,
    arguments,
    workingDirectory: workingDirectory,
  );
  stdout.write(result.stdout);
  stderr.write(result.stderr);
  if (result.exitCode != 0) {
    throw ProcessException(
      executable,
      arguments,
      'Command failed with exit code ${result.exitCode}',
      result.exitCode,
    );
  }
}

String _extensionIdFromManifest(File manifestFile) {
  final decoded = jsonDecode(manifestFile.readAsStringSync());
  if (decoded is! Map<String, dynamic>) {
    throw const FormatException('Extension manifest must be a JSON object.');
  }
  final key = decoded['key'];
  if (key is! String || key.isEmpty) {
    throw StateError(
      'extensions/browser/chrome/manifest.json needs a "key" or pass --extension-id.',
    );
  }
  final digest = _sha256(base64Decode(key)).take(16);
  final buffer = StringBuffer();
  for (final byte in digest) {
    buffer
      ..write(String.fromCharCode(97 + (byte >> 4)))
      ..write(String.fromCharCode(97 + (byte & 0x0f)));
  }
  return buffer.toString();
}

List<int> _sha256(List<int> input) {
  final bytes = _toUint32Bytes(input);
  final bitLength = input.length * 8;
  bytes.add(0x80);
  while ((bytes.length % 64) != 56) {
    bytes.add(0);
  }
  for (var shift = 56; shift >= 0; shift -= 8) {
    bytes.add((bitLength >> shift) & 0xff);
  }

  final h = <int>[
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
  ];
  const k = <int>[
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2,
  ];

  for (var offset = 0; offset < bytes.length; offset += 64) {
    final w = List<int>.filled(64, 0);
    for (var i = 0; i < 16; i++) {
      final j = offset + i * 4;
      w[i] = ((bytes[j] << 24) |
              (bytes[j + 1] << 16) |
              (bytes[j + 2] << 8) |
              bytes[j + 3]) &
          0xffffffff;
    }
    for (var i = 16; i < 64; i++) {
      final s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      final s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
    }

    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];
    var e = h[4];
    var f = h[5];
    var g = h[6];
    var hh = h[7];
    for (var i = 0; i < 64; i++) {
      final s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
      final ch = (e & f) ^ ((~e) & g);
      final temp1 = (hh + s1 + ch + k[i] + w[i]) & 0xffffffff;
      final s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final temp2 = (s0 + maj) & 0xffffffff;
      hh = g;
      g = f;
      f = e;
      e = (d + temp1) & 0xffffffff;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & 0xffffffff;
    }

    h[0] = (h[0] + a) & 0xffffffff;
    h[1] = (h[1] + b) & 0xffffffff;
    h[2] = (h[2] + c) & 0xffffffff;
    h[3] = (h[3] + d) & 0xffffffff;
    h[4] = (h[4] + e) & 0xffffffff;
    h[5] = (h[5] + f) & 0xffffffff;
    h[6] = (h[6] + g) & 0xffffffff;
    h[7] = (h[7] + hh) & 0xffffffff;
  }

  return [
    for (final value in h) ...[
      (value >> 24) & 0xff,
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff
    ],
  ];
}

List<int> _toUint32Bytes(List<int> input) => List<int>.from(input);

int _rotr(int value, int shift) {
  return ((value >> shift) | (value << (32 - shift))) & 0xffffffff;
}

Future<File> _installManifest(File generatedManifest, String browser) async {
  if (Platform.isMacOS || Platform.isLinux) {
    final destination =
        File('${_nativeMessagingDir(browser).path}/$_hostName.json');
    await destination.parent.create(recursive: true);
    await generatedManifest.copy(destination.path);
    return destination;
  }

  if (Platform.isWindows) {
    final destination = File(
      '${Platform.environment['LOCALAPPDATA'] ?? Directory.current.path}'
      '\\flutter_vless\\native_messaging\\$_hostName.chrome.json',
    );
    await destination.parent.create(recursive: true);
    await generatedManifest.copy(destination.path);
    await _run(
      'reg',
      [
        'add',
        r'HKCU\Software\Google\Chrome\NativeMessagingHosts\' + _hostName,
        '/ve',
        '/d',
        destination.absolute.path,
        '/f',
      ],
      workingDirectory: Directory.current.path,
    );
    return destination;
  }

  throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
}

Directory _nativeMessagingDir(String browser) {
  final home = Platform.environment['HOME'] ?? Directory.current.path;
  if (Platform.isMacOS) {
    return switch (browser) {
      'chromium' => Directory(
          '$home/Library/Application Support/Chromium/NativeMessagingHosts',
        ),
      _ => Directory(
          '$home/Library/Application Support/Google/Chrome/NativeMessagingHosts',
        ),
    };
  }
  return switch (browser) {
    'chromium' => Directory('$home/.config/chromium/NativeMessagingHosts'),
    _ => Directory('$home/.config/google-chrome/NativeMessagingHosts'),
  };
}

class _SetupOptions {
  const _SetupOptions({
    required this.browser,
    required this.skipBuild,
    required this.extensionId,
  });

  final String browser;
  final bool skipBuild;
  final String? extensionId;

  static _SetupOptions parse(List<String> args) {
    var browser = 'chrome';
    var skipBuild = false;
    String? extensionId;
    for (final arg in args) {
      if (arg == '--skip-build') {
        skipBuild = true;
      } else if (arg.startsWith('--browser=')) {
        browser = arg.substring('--browser='.length);
      } else if (arg.startsWith('--extension-id=')) {
        extensionId = arg.substring('--extension-id='.length);
      } else {
        stderr.writeln('Unknown argument: $arg');
        _printUsageAndExit();
      }
    }
    return _SetupOptions(
      browser: browser,
      skipBuild: skipBuild,
      extensionId: extensionId,
    );
  }

  static Never _printUsageAndExit() {
    stdout.writeln(
      'Usage: dart run tool/setup_chrome_extension_dev.dart '
      '[--skip-build] [--extension-id=<id>] [--browser=chrome|chromium]',
    );
    exit(64);
  }
}

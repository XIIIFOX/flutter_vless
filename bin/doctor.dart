import 'package:flutter_vless/src/setup/cli.dart';

Future<void> main(List<String> arguments) =>
    runSetupCli(arguments, doctor: true);

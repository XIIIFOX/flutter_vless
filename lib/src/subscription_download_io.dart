import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

/// Downloads a UTF-8 subscription via HTTPS on a supported native platform.
/// URLs and server-provided text are never included in a download error.
Future<String> downloadSubscription(
  Uri url, {
  HttpClient Function()? createClient,
  Duration timeout = const Duration(seconds: 12),
  int maxBytes = 2 * 1024 * 1024,
}) async {
  HttpClient? client;
  try {
    if (!_isHttps(url)) throw _Failure.invalidLink;
    client = createClient?.call() ?? HttpClient();
    return await _download(client, url, maxBytes).timeout(timeout);
  } on _Failure catch (failure) {
    throw FormatException(failure.message);
  } on TimeoutException {
    throw const FormatException('Subscription download timed out.');
  } catch (_) {
    throw const FormatException('Unable to download the subscription.');
  } finally {
    client?.close(force: true);
  }
}

bool _isHttps(Uri url) =>
    url.isScheme('https') && url.host.isNotEmpty && url.userInfo.isEmpty;

Future<String> _download(HttpClient client, Uri url, int maxBytes) async {
  const redirectCodes = {
    HttpStatus.movedPermanently,
    HttpStatus.found,
    HttpStatus.seeOther,
    HttpStatus.temporaryRedirect,
    HttpStatus.permanentRedirect,
  };
  const maxRedirects = 5;
  var target = url.removeFragment();
  for (var redirects = 0;; redirects++) {
    final request = await client.getUrl(target);
    request.followRedirects = false;
    final response = await request.close();

    if (redirectCodes.contains(response.statusCode)) {
      final location = response.headers.value(HttpHeaders.locationHeader);
      if (redirects == maxRedirects || location == null || location.isEmpty) {
        throw _Failure.invalidRedirect;
      }
      target = target.resolve(location).removeFragment();
      if (!_isHttps(target)) throw _Failure.invalidRedirect;
      await response.listen(null).cancel();
      continue;
    }

    if (response.statusCode != HttpStatus.ok) throw _Failure.badStatus;
    if (response.contentLength > maxBytes) throw _Failure.tooLarge;
    final bytes = BytesBuilder(copy: false);
    await for (final chunk in response) {
      if (bytes.length + chunk.length > maxBytes) throw _Failure.tooLarge;
      bytes.add(chunk);
    }
    final content = utf8.decode(bytes.takeBytes());
    if (content.trim().isEmpty) throw _Failure.empty;
    return content;
  }
}

enum _Failure implements Exception {
  invalidLink('Use an HTTPS subscription link.'),
  invalidRedirect('The subscription returned an invalid redirect.'),
  badStatus('The subscription server did not return a list.'),
  tooLarge('The subscription response is too large.'),
  empty('The subscription is empty.');

  const _Failure(this.message);
  final String message;
}

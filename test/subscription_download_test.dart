import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/src/subscription_download_io.dart';

final _url = Uri.parse('https://provider.invalid/subscription?token=private');

Matcher _downloadError(String text) => throwsA(
      isA<FormatException>().having((error) => error.message, 'message', text),
    );

void main() {
  test('reads a UTF-8 response and follows relative HTTPS redirects', () async {
    const payload = 'socks://first.invalid:1080#Один\n'
        'socks://second.invalid:1080#Два';
    final bytes = utf8.encode(payload);
    final client = _Client([
      _Response(302, location: '/updated?token=second'),
      _Response(200,
          chunks: Stream.fromIterable(
              [bytes.take(29).toList(), bytes.skip(29).toList()])),
    ]);

    expect(
        await downloadSubscription(_url, createClient: () => client), payload);
    expect(client.urls, [_url, _url.resolve('/updated?token=second')]);
    expect(client.closed, isTrue);
  });

  test('rejects non-HTTPS and URL user info before creating a client',
      () async {
    for (final url in [
      Uri.parse('http://provider.invalid/subscription'),
      Uri.parse('https://private@provider.invalid/subscription'),
      Uri.parse('https:///subscription'),
    ]) {
      await expectLater(
        downloadSubscription(url,
            createClient: () => throw StateError('unexpected request')),
        _downloadError('Use an HTTPS subscription link.'),
      );
    }
  });

  test('rejects downgraded or invalid redirects without retrying', () async {
    for (final location in [null, '', 'http://untrusted.invalid/private']) {
      final client = _Client([_Response(302, location: location)]);

      await expectLater(
        downloadSubscription(_url, createClient: () => client),
        _downloadError('The subscription returned an invalid redirect.'),
      );
      expect(client.urls, [_url]);
      expect(client.closed, isTrue);
    }
  });

  test('bounds the number of redirects', () async {
    final client =
        _Client(List.generate(6, (_) => _Response(308, location: '/loop')));

    await expectLater(
      downloadSubscription(_url, createClient: () => client),
      _downloadError('The subscription returned an invalid redirect.'),
    );
    expect(client.urls, hasLength(6));
    expect(client.closed, isTrue);
  });

  test('rejects excessive declared or streamed response sizes', () async {
    for (final response in [
      _Response(200, contentLength: 5),
      _Response(200,
          chunks: Stream.fromIterable([
            [1, 2, 3],
            [4, 5]
          ])),
    ]) {
      final client = _Client([response]);

      await expectLater(
        downloadSubscription(_url, createClient: () => client, maxBytes: 4),
        _downloadError('The subscription response is too large.'),
      );
      expect(client.closed, isTrue);
    }
  });

  test('reports HTTP status, empty content, and network failures safely',
      () async {
    for (final (client, message) in [
      (
        _Client([_Response(403)]),
        'The subscription server did not return a list.'
      ),
      (_Client([_Response(200)]), 'The subscription is empty.'),
      (
        _Client([], failure: HttpException('bad response', uri: _url)),
        'Unable to download the subscription.'
      ),
    ]) {
      await expectLater(
        downloadSubscription(_url, createClient: () => client),
        _downloadError(message),
      );
      expect(client.closed, isTrue);
    }
  });

  test('times out a stalled body and closes the client', () async {
    final controller = StreamController<List<int>>();
    addTearDown(controller.close);
    final client = _Client([_Response(200, chunks: controller.stream)]);

    await expectLater(
      downloadSubscription(
        _url,
        createClient: () => client,
        timeout: const Duration(milliseconds: 40),
      ),
      _downloadError('Subscription download timed out.'),
    );
    expect(client.closed, isTrue);
  });

  test('refresh fetches once and carries selection and edits across reorder',
      () async {
    const first = 'socks://first.invalid:1080#First';
    const second = 'socks://second.invalid:1080#Second';
    final previous = XraySubscription.fromProfiles(
      FlutterVless.parseMany('$first\n$second'),
    );
    final id = previous.nodes.first.id;
    final edited = previous.select(id).editProfile(
          id,
          (draft) => draft.setRaw(CorePath.root.key('localSetting'), true),
        );
    final client = _Client([
      _Response(200, chunks: Stream.value(utf8.encode('$second\n$first'))),
    ]);
    final refreshed = await HttpOverrides.runZoned(
      () => FlutterVless.refreshSubscription(_url, edited),
      createHttpClient: (_) => client,
    );
    expect(client.urls, [_url]);
    expect(client.closed, isTrue);
    expect(refreshed.subscription.nodes.last.id, same(id));
    expect(refreshed.subscription.selectedNodeId, same(id));
    expect(refreshed.subscription.selectedNode?.profile.toCoreMap(),
        containsPair('localSetting', true));
  });

  test('refresh failure keeps the previous selection and redacts payload',
      () async {
    final original = XraySubscription.fromProfiles(
      FlutterVless.parseMany('socks://first.invalid:1080#First'),
    );
    final previous = original.select(original.nodes.single.id);
    final client = _Client([
      _Response(200, chunks: Stream.value(utf8.encode('private-payload'))),
    ]);
    await expectLater(
      HttpOverrides.runZoned(
        () => FlutterVless.refreshSubscription(_url, previous),
        createHttpClient: (_) => client,
      ),
      _downloadError('The subscription contains no usable profiles.'),
    );
    expect(previous.selectedNode, same(original.nodes.single));
    expect(client.closed, isTrue);
  });
}

class _Client implements HttpClient {
  _Client(this.responses, {this.failure});

  final List<_Response> responses;
  final Object? failure;
  final urls = <Uri>[];
  bool closed = false;

  @override
  Future<HttpClientRequest> getUrl(Uri url) async {
    urls.add(url);
    if (failure case final problem?) throw problem;
    return _Request(responses[urls.length - 1]);
  }

  @override
  void close({bool force = false}) {
    expect(force, isTrue);
    closed = true;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Request implements HttpClientRequest {
  _Request(this.response);

  final HttpClientResponse response;

  @override
  bool followRedirects = true;

  @override
  Future<HttpClientResponse> close() async {
    expect(followRedirects, isFalse);
    return response;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Response extends Stream<List<int>> implements HttpClientResponse {
  _Response(
    this.statusCode, {
    this.contentLength = -1,
    String? location,
    this.chunks = const Stream.empty(),
  }) : headers = _Headers(location);

  @override
  final int statusCode;
  @override
  final int contentLength;
  @override
  final HttpHeaders headers;
  final Stream<List<int>> chunks;

  @override
  StreamSubscription<List<int>> listen(
    void Function(List<int>)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) =>
      chunks.listen(onData,
          onError: onError, onDone: onDone, cancelOnError: cancelOnError);

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Headers implements HttpHeaders {
  _Headers(this.location);

  final String? location;

  @override
  String? value(String name) {
    expect(name, HttpHeaders.locationHeader);
    return location;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

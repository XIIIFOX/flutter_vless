# GeoDAT gzip with Core 26.10.31

Merge the `geodata` section from [geodat-gzip.json](geodat-gzip.json) into your
complete profile, retaining its routing and outbound tags. The URLs are
placeholders: replace them with trusted HTTPS sources of compatible full
GeoDAT files. This example does not download or enable an updater by itself.

Prepare the existing full `geoip.dat` and `geosite.dat` files in a persistent,
writable `geoAssetsDirectory`. On iOS/macOS VPN this must be a shared App Group
directory accessible to the extension, rather than the application bundle.
The updater target stays `.dat`; only the HTTPS response is compressed.
[The existing updater example](../../geodata/README.md) explains directory,
scheduling and GeoDAT lifetime capability requirements.

Core detects gzip by its first two bytes, not the URL extension. Both example
URLs may therefore serve a gzip body. For an unambiguous server fixture, serve
the compressed file as `application/octet-stream` without HTTP
`Content-Encoding`. A raw GeoDAT at a URL ending in `.gz` is also read as raw
data when its contents are not gzip.

The fixed limit is **256 MiB of decoded data per response**, even when the
compressed file and its Content-Length are small. A corrupt checksum,
truncated gzip stream, empty decoded body or decoded size above that limit
rejects the update. Downloads are staged beside the target before replacement;
a failed batch or cancelled active download must preserve caller files and
remove owned staging. Existing transaction/reload rollback remains in force.
No plugin option raises the Core limit.

The focused acceptance fixture exercises real loopback HTTPS/HTTP2:

* gzip bytes at an ordinary `.dat` URL and raw bytes at a `.gz` URL;
* corrupt header/checksum, truncated header/trailer, empty decoded body and a
  corrupt second gzip member;
* the actual 256 MiB decoded boundary and one byte above it, streamed into a
  counting sink using less than 2 MiB of compressed fixture memory;
* first-stage cleanup on a corrupt second asset, then an exact valid batch
  commit without changing the original files before all downloads succeed;
* Stop during a continuing gzip stream, preserving the original file and
  draining the request, HTTP/2 pool, scheduler and staging.

These synthetic byte fixtures qualify decoding, limits and file ownership;
they do not replace testing your actual regional datasets. The decoded-limit
case does not allocate or write a 256 MiB asset. The fixture is opt-in under
the `flutter_vless_core31_followups` build tag and runs only in Actions; no
native Core is executed on the owner's Mac.

Source: [pinned Core downloader](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/app/geodata/download.go).

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
XRAY_RUNTIME_VERSION="${XRAY_RUNTIME_VERSION:-26.10.29-protect3}"
CENTRAL_PUBLISHING_TYPE="${CENTRAL_PUBLISHING_TYPE:-AUTOMATIC}"
test "$XRAY_RUNTIME_VERSION" = "26.10.29-protect3"
case "$CENTRAL_PUBLISHING_TYPE" in USER_MANAGED|AUTOMATIC) ;; *) exit 2 ;; esac

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"

if [ -d "/Applications/Android Studio.app/Contents/jbr/Contents/Home" ] && [ -z "${JAVA_HOME:-}" ]; then
  export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
fi

if [ -n "${JAVA_HOME:-}" ]; then
  export PATH="$JAVA_HOME/bin:$PATH"
fi

: "${MAVEN_CENTRAL_USERNAME:?Set MAVEN_CENTRAL_USERNAME to your Central Portal token username.}"
: "${MAVEN_CENTRAL_PASSWORD:?Set MAVEN_CENTRAL_PASSWORD to your Central Portal token password.}"
: "${SIGNING_IN_MEMORY_KEY:?Set SIGNING_IN_MEMORY_KEY to an ASCII-armored private GPG key.}"
: "${SIGNING_IN_MEMORY_KEY_PASSWORD:?Set SIGNING_IN_MEMORY_KEY_PASSWORD to the GPG key password.}"

XRAY_BUILD_FRESH_RELEASE=1 XRAY_RUNTIME_VERSION="$XRAY_RUNTIME_VERSION" \
  "$ROOT_DIR/tool/build_android_runtime_maven.sh"

BUNDLE_PATH="$ROOT_DIR/build/android-runtime-release-artifact/xray-android-$XRAY_RUNTIME_VERSION-central-bundle.zip"
AUTH_TOKEN="$(printf '%s:%s' "$MAVEN_CENTRAL_USERNAME" "$MAVEN_CENTRAL_PASSWORD" | base64 | tr -d '\n')"
DEPLOYMENT_NAME="xray-android-$XRAY_RUNTIME_VERSION"
UPLOAD_URL="https://central.sonatype.com/api/v1/publisher/upload?publishingType=$CENTRAL_PUBLISHING_TYPE&name=$DEPLOYMENT_NAME"

DEPLOYMENT_ID="$(
  curl --fail --show-error --silent \
    --request POST \
    --header "Authorization: Bearer $AUTH_TOKEN" \
    --form "bundle=@$BUNDLE_PATH" \
    "$UPLOAD_URL"
)"

echo "Uploaded Maven Central deployment: $DEPLOYMENT_ID"
echo "Publishing type: $CENTRAL_PUBLISHING_TYPE"
echo "Status URL: https://central.sonatype.com/publishing/deployments"
DEPLOYMENT_ID="$DEPLOYMENT_ID" python3 - "$ROOT_DIR/build/android-runtime-release-artifact/central-deployment.json" <<'PY'
import json,os,re,sys
from pathlib import Path
identity=os.environ['DEPLOYMENT_ID'].strip()
if not re.fullmatch(r'[A-Za-z0-9-]{8,128}',identity):
    raise SystemExit('Ambiguous Central upload response; recover status, do not upload again')
Path(sys.argv[1]).write_text(json.dumps({'deployment_id':identity,'state':'UPLOADED','published':False})+'\n')
PY

if [ "$CENTRAL_PUBLISHING_TYPE" = AUTOMATIC ]; then
  status_file="$ROOT_DIR/build/android-runtime-release-artifact/central-status.json"
  publish_deadline=$((SECONDS + 1800))
  while true; do
    # Status is read-only and always targets the one returned deployment ID.
    # A status failure must never upload or build a second bundle.
    curl --fail --show-error --silent --max-time 30 --retry 2 --retry-delay 2 \
      --request POST --header "Authorization: Bearer $AUTH_TOKEN" \
      "https://central.sonatype.com/api/v1/publisher/status?id=$DEPLOYMENT_ID" \
      --output "$status_file"
    state="$(DEPLOYMENT_ID="$DEPLOYMENT_ID" python3 - "$status_file" <<'PY'
import datetime,json,os,sys
from pathlib import Path
path=Path(sys.argv[1]);status=json.loads(path.read_text())
state=status.get('deploymentState')
if state not in ('PENDING','VALIDATING','VALIDATED','PUBLISHING','PUBLISHED','FAILED'):
    raise SystemExit('Unknown Central publication state; inspect saved status, do not reupload')
record={'deployment_id':os.environ['DEPLOYMENT_ID'],'state':state,'published':state=='PUBLISHED',
        'observed_UTC':datetime.datetime.now(datetime.timezone.utc).isoformat()}
(path.parent/'central-deployment.json').write_text(json.dumps(record)+'\n')
with (path.parent/'central-status-history.jsonl').open('a') as history:
    history.write(json.dumps(record)+'\n')
print(state)
PY
)"
    echo "Deployment $DEPLOYMENT_ID state: $state"
    case "$state" in
      PUBLISHED) exit 0 ;;
      FAILED) echo "Central validation failed; exact errors retained in central-status.json" >&2; exit 1 ;;
    esac
    if [ "$SECONDS" -ge "$publish_deadline" ]; then
      echo "Timed out waiting for the same Central deployment; status and exact bundle retained." >&2
      exit 1
    fi
    sleep 15
  done
fi

#!/usr/bin/env bash
set -euo pipefail

target=$1
cli_bin=$2
gui_bin=$3
version=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
name="senbei-$version-$target"
stage="stage/$name"
mkdir -p "$stage"
cp "target/release/$cli_bin" LICENSE README.md "$stage/"
cp senbei-gui/assets/fonts/OFL.txt "$stage/ASUL-OFL.txt"
awk '/^## Legal notice and intended use/{f=1} f && /^## / && !/Legal notice/{exit} f' \
  README.md > "$stage/LEGAL-NOTICE.md"

if [[ $target == *-apple-darwin ]]; then
  app="$stage/Senbei.app"
  contents="$app/Contents"
  mkdir -p "$contents/MacOS" "$contents/Resources"
  cp "target/release/$gui_bin" "$contents/MacOS/"
  sips -s format icns senbei-gui/assets/icon-256.png \
    --out "$contents/Resources/Senbei.icns" >/dev/null
  cat > "$contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>$gui_bin</string>
  <key>CFBundleIconFile</key>
  <string>Senbei.icns</string>
  <key>CFBundleIdentifier</key>
  <string>moe.momokko.senbei</string>
  <key>CFBundleName</key>
  <string>Senbei</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$version</string>
  <key>CFBundleVersion</key>
  <string>$version</string>
</dict>
</plist>
EOF
  plutil -lint -s "$contents/Info.plist"
  codesign --force --sign - "$app"
  codesign --verify --strict "$app"
  ditto -c -k --keepParent "$stage" "stage/$name.zip"
else
  cp "target/release/$gui_bin" "$stage/"
fi

echo "$name"

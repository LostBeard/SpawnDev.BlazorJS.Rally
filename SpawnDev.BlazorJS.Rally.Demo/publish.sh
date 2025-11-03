#!/usr/bin/bash

rm -rf "bin/Publish/"
echo "Normal build with SIMD and BlazorWebAssemblyJiterpreter enabled (.Net 8 defaults)"
dotnet publish --nologo -v q --property WarningLevel=0 /clp:ErrorsOnly --configuration Release -p:PublishTrimmed=false --output "bin/Publish"

if [ $? -ne 0 ]; then
    echo "Normal build failed"
    exit 1
fi

rm -rf "bin/PublishCompat/"
echo "ReleaseCompat build with SIMD and BlazorWebAssemblyJiterpreter disabled"
dotnet publish --nologo -v q --property WarningLevel=0 /clp:ErrorsOnly --configuration Release -p:PublishTrimmed=false -p:WasmEnableSIMD=false -p:BlazorWebAssemblyJiterpreter=false -p:WasmEnableExceptionHandling=false --output "bin/PublishCompat"
if [ $? -ne 0 ]; then
    echo "Compat build failed"
    exit 1
fi

echo "Combine builds"
echo "Copy the 'wwwroot/_framework' folder contents from the 2nd build to 'wwwroot/_frameworkCompat' in the 1st build"
cp -r "bin/PublishCompat/wwwroot/_framework/." "bin/Publish/wwwroot/_frameworkCompat"

echo "Clean up"
rm -rf "bin/PublishCompat/"

: '
echo "If building a PWA app with server-worker-assets.js the service-worker script needs to be modified to also detect SIMD and cache the appropriate build"
echo "Copy the service-worker-assets.js from the 2nd build to 'service-worker-assets-compat.js' of the 1st build"
cp "bin/PublishCompat/wwwroot/service-worker-assets.js" "bin/Publish/wwwroot/service-worker-assets-compat.js"
'
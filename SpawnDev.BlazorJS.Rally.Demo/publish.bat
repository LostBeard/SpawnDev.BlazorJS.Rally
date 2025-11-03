

rmdir /Q /S "bin\Publish\"
echo "Normal build with SIMD and BlazorWebAssemblyJiterpreter enabled (.Net 8 defaults)"
dotnet publish --nologo -v q --property WarningLevel=0 /clp:ErrorsOnly --configuration Release -p:PublishTrimmed=false --output "bin\Publish"

rmdir /Q /S "bin\PublishCompat\"
echo "ReleaseCompat build with SIMD and BlazorWebAssemblyJiterpreter disabled"
dotnet publish --nologo -v q --property WarningLevel=0 /clp:ErrorsOnly --no-restore --configuration Release -p:PublishTrimmed=false -p:WasmEnableSIMD=false -p:BlazorWebAssemblyJiterpreter=false -p:WasmEnableExceptionHandling=false --output "bin\PublishCompat"

echo "Combine builds"
echo "Copy the 'wwwroot\_framework' folder contents from the 2nd build to 'wwwroot\_frameworkCompat' in the 1st build"
xcopy /I /E /Y "bin\PublishCompat\wwwroot\_framework" "bin\Publish\wwwroot\_frameworkCompat"

echo "If building a PWA app with server-worker-assets.js the service-worker script needs to be modified to also detect SIMD and cache the appropriate build"
echo "Copy the service-worker-assets.js from the 2nd build to 'service-worker-assets-compat.js' of the 1st build"
copy /Y "bin\PublishCompat\wwwroot\service-worker-assets.js" "bin\Publish\wwwroot\service-worker-assets-compat.js"


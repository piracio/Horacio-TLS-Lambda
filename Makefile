build:
		dotnet build ./src/Horacio-TLS-Lambda.Local/Horacio-TLS-Lambda.Local.csproj -c Release

run:
		dotnet run --project ./src/Horacio-TLS-Lambda.Local/Horacio-TLS-Lambda.Local.csproj -c Release -- "https://google.com"

clean:
		dotnet clean ./src/Horacio-TLS-Lambda.Local/Horacio-TLS-Lambda.Local.csproj -c Release

distclean:
		rm -rf ./src/Horacio-TLS-Lambda.Local/bin ./src/Horacio-TLS-Lambda.Local/obj

install-lambda-test-tool:
		@dotnet tool list -g | grep -q Amazon.Lambda.TestTool-8.0 || dotnet tool install -g Amazon.Lambda.TestTool-8.0

# Run AWS Lambda Test Tool against the Lambda project (Debug output).
# Important: run from the Lambda project directory so the tool does not auto-detect the .Local project.
local: install-lambda-test-tool
		cd ./src/Horacio-TLS-Lambda && dotnet build -c Debug && dotnet lambda-test-tool-8.0

# Optional: build the Lambda project (Release)
build-lambda:
		dotnet build ./src/Horacio-TLS-Lambda/Horacio-TLS-Lambda.csproj -c Release

# Optional: package the Lambda zip (Release)
package:
		cd ./src/Horacio-TLS-Lambda && dotnet lambda package -c Release --output-package Horacio-TLS-Lambda.zip


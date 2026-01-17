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

local:
		dotnet lambda-test-tool-8.0

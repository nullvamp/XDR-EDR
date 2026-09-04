FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props NuGet.Config global.json ./
COPY shared/Platform.Shared/Platform.Shared.csproj shared/Platform.Shared/
COPY agent/core/Platform.Agent/Platform.Agent.csproj agent/core/Platform.Agent/
RUN dotnet restore agent/core/Platform.Agent/Platform.Agent.csproj
COPY shared shared
COPY agent agent
RUN dotnet publish agent/core/Platform.Agent/Platform.Agent.csproj -c Release -o /out --no-restore
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine
RUN addgroup -S platform \
    && adduser -S -G platform -h /app platform \
    && mkdir -p /data \
    && chown platform:platform /data
WORKDIR /app
COPY --from=build --chown=platform:platform /out ./
USER platform
ENTRYPOINT ["dotnet","Platform.Agent.dll"]

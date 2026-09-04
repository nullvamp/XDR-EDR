FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:306301580fcaa5b445180e759db59309979002d1000669cb4cf58a567d0014bc AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props NuGet.Config global.json ./
COPY shared/Platform.Shared/Platform.Shared.csproj shared/Platform.Shared/
COPY infrastructure/Platform.Infrastructure/Platform.Infrastructure.csproj infrastructure/Platform.Infrastructure/
COPY backend/Platform.ServiceHost/Platform.ServiceHost.csproj backend/Platform.ServiceHost/
RUN dotnet restore backend/Platform.ServiceHost/Platform.ServiceHost.csproj
COPY shared shared
COPY infrastructure infrastructure
COPY backend backend
COPY frontend frontend
RUN dotnet publish backend/Platform.ServiceHost/Platform.ServiceHost.csproj -c Release -o /out --no-restore
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine@sha256:b288317d8ed45bb763fa95dbc807cf9d36e3bf9373ec2fac6b6548675f1f4b23
ARG PRODUCT_VERSION=1.0.0
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.title="Open Security Platform Gateway" \
      org.opencontainers.image.version="$PRODUCT_VERSION" \
      org.opencontainers.image.revision="$SOURCE_REVISION" \
      org.opencontainers.image.vendor="Open Security Platform" \
      org.opencontainers.image.licenses="Proprietary"
RUN apk add --no-cache krb5-libs \
    && addgroup -S platform \
    && adduser -S -G platform -h /app platform \
    && mkdir -p /data \
    && chown platform:platform /data
WORKDIR /app
COPY --from=build --chown=platform:platform /out ./
COPY --chown=platform:platform frontend /frontend
USER platform
ENV ASPNETCORE_URLS=http://+:8080 PLATFORM_DATA_DIRECTORY=/data PLATFORM_FRONTEND_ROOT=/frontend
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD wget -q -T 3 -O /dev/null http://127.0.0.1:8080/health/live || exit 1
ENTRYPOINT ["dotnet","Platform.ServiceHost.dll"]

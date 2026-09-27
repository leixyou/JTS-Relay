FROM mcr.microsoft.com/dotnet/sdk:10.0.401 AS build
WORKDIR /source
COPY global.json Directory.Build.props NuGet.Config ./
COPY src/ src/
RUN dotnet restore src/JTS.Relay.Server/JTS.Relay.Server.csproj --locked-mode
RUN dotnet publish src/JTS.Relay.Server/JTS.Relay.Server.csproj -c Release --no-restore -o /out /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0.12
WORKDIR /app
COPY --from=build /out/ ./
COPY third-party/ /usr/share/doc/jts-relay/third-party/
RUN mkdir -p /var/lib/jts-relay && chown "$APP_UID:$APP_UID" /var/lib/jts-relay && chmod 0700 /var/lib/jts-relay
USER $APP_UID
EXPOSE 8443
ENTRYPOINT ["dotnet", "JTS.Relay.Server.dll", "--config", "/etc/jts-relay/relay.json"]

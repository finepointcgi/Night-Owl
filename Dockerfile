# The Night Owl dashboard as a container: browse saved scans, triage, exports and STIG checklists.
# Scans themselves run with the CLI (in CI or on a workstation) and write to the same NIGHTOWL_HOME, mounted at /data.
#   docker build -t nightowl-dashboard .
#   docker run -p 5212:8080 -v nightowl-data:/data -e NIGHTOWL_OIDC_AUTHORITY=… -e NIGHTOWL_OIDC_CLIENT_ID=… nightowl-dashboard
# Listening on the network needs single sign-on (NIGHTOWL_OIDC_*) or NIGHTOWL_DASHBOARD_TOKEN; it refuses to start otherwise.
ARG DOTNET_VERSION=10.0

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
WORKDIR /src
COPY . .
RUN dotnet publish src/NightOwl.Web/NightOwl.Web.csproj -c Release -o /app --nologo

FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_VERSION}
WORKDIR /app
COPY --from=build /app .
ENV NIGHTOWL_HOME=/data \
    ASPNETCORE_URLS=http://0.0.0.0:8080
RUN mkdir -p /data && chown app:app /data
USER app
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["dotnet", "/app/NightOwl.Web.dll"]

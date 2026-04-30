FROM gcr.io/distroless/java21-debian13:nonroot

COPY build/install/*/lib /app/lib

ENTRYPOINT ["java", "-cp", "/app/lib/*", "io.nais.security.oauth2.TokenExchangeAppKt"]

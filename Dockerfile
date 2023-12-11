FROM gcr.io/distroless/java21-debian12:nonroot

COPY build/libs/app-*.jar /app/app.jar

WORKDIR /app

CMD ["app.jar"]


FROM gcr.io/distroless/java17

COPY build/libs/app-*.jar /app/app.jar

WORKDIR /app

CMD ["app.jar"]


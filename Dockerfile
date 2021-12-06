FROM navikt/java:17
COPY build/libs/app-*.jar "/app/app.jar"

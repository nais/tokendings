FROM navikt/java:11
COPY build/libs/app-*.jar "/app/app.jar"

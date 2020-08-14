FROM navikt/java:14
COPY build/libs/app-*.jar "/app/app.jar"

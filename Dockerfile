FROM navikt/java:15
COPY build/libs/app-*.jar "/app/app.jar"

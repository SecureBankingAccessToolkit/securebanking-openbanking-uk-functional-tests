FROM azul/zulu-openjdk-alpine:23-latest

COPY src /opt/functional-tests/src
COPY build.gradle.kts /opt/functional-tests/build.gradle.kts
COPY settings.gradle.kts /opt/functional-tests/settings.gradle.kts
COPY gradle /opt/functional-tests/gradle
COPY gradlew /opt/functional-tests/gradlew

WORKDIR /opt/functional-tests

RUN ./gradlew compileTestKotlin

CMD ["./gradlew", "cleanTest", "tests_v3_1_10", "-i", "-Djunit.jupiter.extensions.autodetection.enabled=true"]

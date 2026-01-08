# Build MegaBasterd fat JAR
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /build

COPY pom.xml ./
COPY src ./src

RUN mvn -q -DskipTests package


# Runtime: run Swing UI in virtual X server and expose via noVNC
FROM eclipse-temurin:17-jre-jammy

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        fluxbox \
        iproute2 \
        novnc \
        strongswan \
        libcharon-extra-plugins \
        websockify \
        x11vnc \
        xvfb \
    && rm -rf /var/lib/apt/lists/*

ENV DISPLAY=:0
ENV HOME=/config

WORKDIR /app

# Copy the shaded/assembly JAR produced by maven-assembly-plugin
COPY --from=build /build/target/*jar-with-dependencies.jar /app/megabasterd.jar

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME ["/config", "/downloads"]

EXPOSE 6080

ENTRYPOINT ["/entrypoint.sh"]

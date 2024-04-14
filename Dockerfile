FROM openjdk:17-alpine

EXPOSE 8285

COPY ./target/api-gateway-*.jar api-gateway.jar

ENTRYPOINT ["java", "-jar", "api-gateway.jar"]
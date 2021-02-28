FROM openjdk:11

WORKDIR /app

COPY ./target/eseal-1.0.0.jar ./eseal.jar
CMD ["java" ,"-jar", "eseal.jar"]
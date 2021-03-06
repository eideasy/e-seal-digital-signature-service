FROM arm64v8/ubuntu:20.04
#FROM ubuntu:20.04
WORKDIR /app
RUN apt-get update
RUN apt-get install -y apt-utils
#RUN apt-get upgrade -y
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install opensc openjdk-11-jre ykcs11

COPY ./libs/start.sh ./start.sh

COPY ./target/eseal-1.0.0.jar ./eseal.jar
CMD ["bash" ,"start.sh"]
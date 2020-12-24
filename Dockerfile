FROM ubuntu:20.04
WORKDIR /app
RUN apt-get update
RUN apt-get install -y ap-utils
#RUN apt-get upgrade -y
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install opensc openjdk-11-jre

COPY ./libs/start.sh ./start.sh

COPY ./libs/libIDPrimePKCS11.so /usr/lib/libIDPrimePKCS11.so
COPY ./target/eseal-1.0.0.jar ./eseal.jar
CMD ["bash" ,"start.sh"]
#FROM arm64v8/ubuntu:20.04
FROM ubuntu:20.04
WORKDIR /app

COPY ./libs/start.sh ./start.sh

# Only if Safenet eToken is used
COPY ./libs/safenetauthenticationclient-core_10.7.77_amd64.deb ./safenetauthenticationclient-core_10.7.77_amd64.deb

RUN apt-get update
RUN apt-get install -y apt-utils
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install opensc openjdk-11-jre ykcs11

# Only if Safenet eToken is used
RUN dpkg -i ./safenetauthenticationclient-core_10.7.77_amd64.deb

COPY ./target/eseal-1.0.0.jar ./eseal.jar
CMD ["bash" ,"start.sh"]
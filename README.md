# e-Sealing digital signature service for eID Easy

This application will allow you to add e-Seal/e-Stamp/Digital Stamp to the documents using eID Easy while keeping full
control of your document signing certificate.

When you initiate adding e-Seal to the document then eID Easy will make request to this service to get the PKCS #1
signature that will be added to the ASIC-E container or to the PDF as PAdES signature

Recommended HSM is YubiKey FIPS since it has arm64 compatible PKCS #11 libraries.

### Notes on Google Cloud HSM ###

If you are using Google Cloud HSM then you can use branch google-cloud-hsm-only. Make sure you have Google application
credentials generated. Check https://cloud.google.com/docs/authentication/getting-started if needed. If needed then you
could modify Dockerfile to include the credentials also in the image.

Add these properties when running the image to set docker machine environment and mount the volume with application
credentials file location

```
sudo docker run -d --env-file ~/.env-eseal -p 8080:8082 --name=eideasy_eseal --restart always -v /path/to/credentials.json:/tmp/keys/google-credentials.json:ro -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/keys/google-credentials.json --log-driver syslog --log-opt tag="{{.Name}}/{{.ID}}" eideasy/eseal
```

### To run this service you need to

- get hmac_key from eID Easy
- configure environment variables shown in src/main/resources/application.properties.example
- run and make the service accessible to the eID Easy API server

### Build instructions

  ```
    # Install the PKCS #11 required library to maven if needed 
    mvn install:install-file -Dfile=/YOUR FOLDER/iaikPkcs11Wrapper_1.6.2.jar -DgroupId=pkcs11 -DartifactId=iaikWrapper -Dversion=1.0 -Dpackaging=jar -DgeneratePom=true
    
    mvn clean package
    docker build --no-cache . -t eideasy/eseal
    docker system prune
    docker save --output eseal.tar eideasy/eseal
  ```

### Deployment instructions on Raspberry PI

1. Copy the docker machine to your Raspberry or other device and load it. Assuming you have installed ubuntu server at IP
   192.168.8.240 then follow these commands
   ```
   rsync -avz --progress eseal.tar rock@192.168.8.238:/home/rock
   ssh ubuntu@192.168.8.240
   
   # In Raspverry PI machine
   sudo docker load --input /home/rock/eseal.tar
   ```

2. create environment variables file to ~/.env-eseal. Check src/main/resources/application.properties.example

3. Run the docker container and remove old instances if needed
    ```
   sudo docker stop eideasy_eseal -t 0
   sudo docker rm eideasy_eseal 
   sudo docker run -d --env-file ~/.env-eseal --device=/dev/bus/usb -p 127.0.0.1:9080:8082 --name=eideasy_eseal --restart always --log-driver syslog --log-opt tag="{{.Name}}/{{.ID}}" eideasy/eseal   
    ```

### Contact and support

More details from info@eideasy.com

This product includes software developed by IAIK of Graz University of Technology.
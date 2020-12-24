# e-Sealing digital signature service for eID Easy 

This application will allow you to add e-Seal/e-Stamp/Digital Stamp to the documents using eID Easy while keeping full control of your document signing certificate.

When you initiate adding e-Seal to the document then eID Easy will make request to this service to get the PKCS #1 signature that will be added to the ASIC-E container or to the PDF as PAdES signature

### To run this service you need to

- get hmac_key from eID Easy
- configure environment variables shown in src/main/resources/application.properties.example
- run and make the service accessible to the eID Easy API server

### Build instructions
When the e-seal certificates are on Gemalto SafeNet eToken 5110 IDprime device
and this application is running on the ARM device like Raspberry PI then docker is recommended for now
because this crypto token is missing linux PKCS #11 libraries for aarch64 architecture.  

  ```
    $ mvn clean package
    $ docker build --no-cache . -t eideasy/eseal
    $ docker save --output eseal.tar eideasy/eseal
  ```

### Deployment instructions on Raspberry PI

1. Copy the docker machine to your raspberry and load it.
   Assuming you have installed ubuntu server to the PI at 192.168.8.240 then follow these commands
   ```
   $ rsync -avz --progress eseal.tar ubuntu@192.168.8.240:/home/ubuntu
   $ ssh ubuntu@192.168.8.240
   
   In Raspverry PI machine
   $ sudo docker load --input /home/ubuntu/eseal.tar
   ```
   
2. Run the docker container
    ```
   $ sudo docker rm eideasy_eseal 
   $ sudo docker run --device=/dev/bus/usb --name=eideasy_eseal --restart always --log-driver syslog --log-opt tag="{{.Name}}/{{.ID}}" eideasy/eseal
    ```

### Contact and more info

More details from info@eideasy.com



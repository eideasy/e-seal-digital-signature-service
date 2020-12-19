# e-Sealing digital signature service for eID Easy 

This application will allow you to add e-Seal/e-Stamp/Digital Stamp to the documents using eID Easy while keeping full control of your document signing certificate.

When you initiate adding e-Seal to the document then eID Easy will make request to this service to get the PKCS #1 signature that will be added to the ASIC-E container or to the PDF as PAdES signature

### To run this service you need to

- get hmac_key from eID Easy
- configure environment variables shown in src/main/resources/application.properties.example
- run and make the service accessible to the eID Easy API server

### Contact and more info

More details from info@eideasy.com



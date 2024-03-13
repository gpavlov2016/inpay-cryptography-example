# NODE EXAMPLE

## Summary

This utility implements two complete examples of how to `Sign and Encrypt`, and `Decrypt and Verify` a message using the InPay API.

## How to use it

1. Obtain your credentials from InPay. You will need a merchant certificate and a private key. You will also need a UUID and a SECRET.

2. Add the merchant certificate and the private key to the `credentials` folder.

3. Copy the .env.example file to .env and update the values with your credentials.

```
CLIENT_UUID=''
CLIENT_SECRET=''
MERCHANT_CERTIFICATE_FILENAME=''
PRIVATE_KEY_FILENAME=''
```

4. Run `npm install` to install the dependencies.

5. Run `npm start` to run the example.

import forge from 'node-forge';
import fetch from 'node-fetch';
import { readFileSync } from 'fs';
import { join } from 'path';
import { v4 as uuidv4 } from 'uuid';
import 'dotenv/config'

const { pkcs7, asn1, pki } = forge;

const API_CLIENT_UUID = process.env.CLIENT_UUID;
const API_CLIENT_SECRET = process.env.CLIENT_SECRET;
const API_URL = 'https://test-api.inpay.com/';

export default class Cryptographer {
  constructor(credentialsFolder) {
    this._credentialsFolder = credentialsFolder;
  }

  async sign_and_encrypt() {
    // Read credentials
    const merchantCertificate = this._readCredentialsFile(process.env.MERCHANT_CERTIFICATE_FILENAME);
    const merchantPrivate = this._readCredentialsFile(process.env.PRIVATE_KEY_FILENAME);
    const inpayCertificate = this._readCredentialsFile('inpay_certificate.crt');

    // Define API request payload
    const payload = JSON.stringify({
      amount: "100.00",
      currency_code: "EUR",
      end_to_end_id: "Te4fw612356df4",
      local_instrument: "SEPA",
      remittance_description: "Birthday gift",
      creditor: {},
      creditor_account: {},
      ultimate_debtor: {
        type: "private",
        name: "Joe Doe",
        address_lines: "Lietzenburger Straße 63",
        postcode: "49762",
        city: "Renkenberge",
        country_code: "CY"
      },
      debtor: {
        name: "Test"
      },
      debtor_account: {
        scheme_name: "VirtualAccount",
        id: "3"
      }
    });

    // Sign the payload using the merchant's private key and certificate
    const sign = pkcs7.createSignedData();
    sign.content = forge.util.createBuffer(payload);
    sign.addSigner({ key: merchantPrivate, certificate: merchantCertificate });
    sign.sign();

    // Initialize empty PKCS7 enveloped data object
    const p7 = pkcs7.createEnvelopedData();
    // Convert InPay certificate to Forge certificate object 
    const cert = pki.certificateFromPem(inpayCertificate);
    // Add InPay certificate to the PKCS7 enveloped data object
    p7.addRecipient(cert);

    // Convert signed data to DER and add it to the PKCS7 enveloped data object
    const der = asn1.toDer(sign.toAsn1());
    p7.content = forge.util.createBuffer(der);
    // Encrypt the signed data with the public key of the recipient (InPay)
    // Public key is extracted from the receiver's certificate
    p7.encrypt();

    // Convert the PKCS7 enveloped data object to PEM format
    const pem = pkcs7.messageToPem(p7);
    console.log('Signed and encrypted message:\n', pem);

    // Send the encrypted message to InPay's API
    const response = await fetch(
      `${API_URL}/authorization/checks/encryption`,
      {
        method: 'POST',
        headers: {
          'X-Auth-Uuid': API_CLIENT_UUID,
          'Authorization': 'Bearer ' + API_CLIENT_SECRET,
          'X-Request-ID': uuidv4()
        },
        body: pem
      }
    );

    // Log the response from InPay's API
    const data = await response.text();
    console.log('Response from API:\n', data);
  }

  async decrypt_and_verify() {
    // Request encrypted message from InPay's API
    const response = await fetch(
      `${API_URL}/authorization/checks/decryption`,
      {
        method: 'POST',
        headers: {
          'X-Auth-Uuid': API_CLIENT_UUID,
          'Authorization': 'Bearer ' + API_CLIENT_SECRET,
          'X-Request-ID': uuidv4()
        },
        body: 'Plaintext to test decryption.'
      }
    );

    // Print the encrypted message received from InPay's API
    const data = await response.text();
    console.log('Signed and encrypted message sent by Inpay:\n', data);

    // Read merchant's private key and InPay's certificate
    const merchantPrivatePem = this._readCredentialsFile('merchant-private.key')
    const merchantPrivate = forge.pki.privateKeyFromPem(merchantPrivatePem);
    
    // Initialize PKCS7 object from the encrypted data
    const p7 = forge.pkcs7.messageFromPem(data);

    // Decrypt the encrypted message using the merchant's private key
    p7.decrypt(p7.recipients[0], merchantPrivate);

    // Convert the decrypted data to ASN.1
    const decryptedData = forge.asn1.fromDer(p7.content.data);
    // Initialize another PKCS7 object from the decrypted data
    const signedP7 = forge.pkcs7.messageFromAsn1(decryptedData);

    // Extract the message (should match the API request body) from the PKCS7 object
    const message = signedP7.rawCapture.content.value[0].value;
    const encodedMessage = forge.util.encodeUtf8(message);

    // Read InPay certificate and convert it to a Forge certificate object
    const inpayCertificate = this._readCredentialsFile('inpay_certificate.crt');
    const inpayCert = pki.certificateFromPem(inpayCertificate);

    // Decrypt the signature using InPay's public key and encode in Base64
    const decryptedSignature = pki.rsa.decrypt(signedP7.rawCapture.signature, inpayCert.publicKey, true, false);
    const decryptedEncodedSignature = forge.util.encode64(decryptedSignature);

    // Extract authenticated attributes field from the PKCS7 object
    const authenticatedAttributes = signedP7.rawCapture.authenticatedAttributes;

    // Calculate the digest of the authenticated attributes and the message, encode in Base64
    const digest = this.calculateDigest(authenticatedAttributes, encodedMessage);
    const encodedDigest = forge.util.encode64(digest);

    // Discard PKCS7 padding from the decrypted signature
    const unpaddedSignature = decryptedEncodedSignature.slice(-encodedDigest.length);

    // Compare the decrypted signature with the calculated digest
    const verified = encodedDigest === unpaddedSignature;

    // Log the decrypted message and result of the verification
    console.log('Decrypted message:', message);
    console.log('Verified:', verified);
  }

  // Calculate the digest of the authenticated attributes and the message based per RFC 2315
  calculateDigest(authenticatedAttributes, encodedMessage) {
    // process authenticated attributes
    // [0] IMPLICIT
    const authenticatedAttributesAsn1 = asn1.create(
      asn1.Class.CONTEXT_SPECIFIC, 0, true, []);

    // per RFC 2315, attributes are to be digested using a SET container
    // not the above [0] IMPLICIT container
    var attrsAsn1 = asn1.create(
      asn1.Class.UNIVERSAL, asn1.Type.SET, true, []);

    // Iterate over authenticated attributes list
    for (var ai = 0; ai < authenticatedAttributes.length; ++ai) {
      const attr = authenticatedAttributes[ai];
      // Covert attribute OID from DER to string
      const attrTypeOid = asn1.derToOid(attr.value[0].value);
     
      // If the attribute is a message digest, 
      // replace the value with independently calculated content message digest 
      if (attrTypeOid === forge.pki.oids.messageDigest) {
        // Calculate the SHA-256 digest of the message encoded in utf-8
        const digest = forge.md.sha256.create().start().update(encodedMessage).digest().bytes();
        // Replace the message digest value in the attribute with calculated digest
        attr.value[1].value[0].value = digest;
      }

      // Add attribute object in ASN.1 format to attribute list to digest
      attrsAsn1.value.push(attr);
    }

    // DER-serialize and calculate SHA256 digest of the attribute list
    const bytes = asn1.toDer(attrsAsn1).getBytes();
    const digest = forge.md.sha256.create();
    digest.start().update(bytes);
    return digest.digest().data;
  }

  // Helper function to read the contents of a file
  _readCredentialsFile(filePath) {
    try {
      const data = readFileSync(join(this._credentialsFolder, filePath), 'utf8')
      return data;
    } catch (err) {
      console.error(err)
    }
  }
}


async function mainModule() {
  // Initialize class instance with the folder containing the credentials
  const crypto = new Cryptographer('credentials')

  // Run both encryption and decryption examples
  await crypto.sign_and_encrypt();
  console.log('---------------------')
  await crypto.decrypt_and_verify();
}

mainModule();

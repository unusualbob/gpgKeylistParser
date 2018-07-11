GPG Key-List Parser
===================

This is a basic parser for the GPG `--list-sigs` and `--list-keys` outputs that use `--with-colons` format.

Format reference used was this: https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS

I couldn't find any javascript based parsers so I wrote my own. Support for crts or other non-gpg keys is likely non-existent. Please double
check what it actually outputs is correct for your use case. I only had one real use case for this util so some use cases may use
functionality I did not build out or test.

## Install
```npm install gpg-keylist-parser```

## Output
See example files for usage, output of the utility itself will be an array of objects which look something like:

```js
{
  "longKeyId": String,
  "created": String,
  "expires": Boolean,
  "keyCapabilities": {
    "encrypt": Boolean,
    "sign": Boolean,
    "certify": Boolean,
    "authentication": Boolean,
    "disabled": Boolean,
    "additionalUnknownCapabilities": Boolean
  },
  "trust": String,
  "bits": Number,
  "signatures": [
    {
      "longKeyId": String,
      "created": String,
      "expires": Boolean,
      "userId": String,
      "signatureClass": String
    },
    ...
  ],
  "userIds": [
    {
      "longKeyId": String,
      "created": String,
      "expires": Boolean,
      "trust": String,
      "uidHash": String,
      "userId": String
    },
    ...
  ],
  "subKeys": [
    {
      "longKeyId": String,
      "created": String,
      "expires": Boolean,
      "keyCapabilities": {
        "encrypt": Boolean,
        "sign": Boolean,
        "certify": Boolean,
        "authentication": Boolean,
        "disabled": Boolean,
        "additionalUnknownCapabilities": Boolean
      },
      "trust": String,
      "bits": Number,
      "signatures": [
        {
          "longKeyId": String,
          "created": String,
          "expires": Boolean,
          "userId": String,
          "signatureClass": String
        },
        ...
      ],
      "fingerprint": String
    }
  ],
  "userAttributes": [],
  "fingerprint": String
}
```

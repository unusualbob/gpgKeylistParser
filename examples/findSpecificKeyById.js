const spawn = require('child_process').spawn;
const GpgParser = require('../index');

let keyId = process.argv[2];
if (!keyId) {
  return console.log('Usage: ./findSpecificKeyById <pgpKeyId>')
}

function checkShortKeyId(key) {
  return key.fingerprint.substr(-8) === keyId;
}

function checkLongKeyId(key) {
  return key.fingerprint.substr(-16) === keyId;
}

function checkWholeKey(key) {
  return key.fingerprint === keyId;
}

async function getTrustedKeyFingerprints() {
  let gpgOutput = spawn('gpg', ['--list-sigs', '--with-colons']);
  let allKeys = await new GpgParser(gpgOutput.stdout);
  let checkKeyId;

  // Use different ways of checking key based on what kind was provided
  if (keyId.length === 8) {
    checkKeyId = checkShortKeyId;
  } else if (keyId.length === 16) {
    checkKeyId = checkLongKeyId;
  } else {
    checkKeyId = checkWholeKey;
  }
  return allKeys.filter(checkKeyId);
}

getTrustedKeyFingerprints().then((keys) => {
  console.log(JSON.stringify(keys[0], null, 2));
}).catch((e) => {
  console.log('Error', e);
});

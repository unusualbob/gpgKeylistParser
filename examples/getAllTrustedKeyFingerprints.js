const spawn = require('child_process').spawn;
const GpgParser = require('../index');

async function getTrustedKeyFingerprints() {
  let gpgOutput = spawn('gpg', ['--list-sigs', '--with-colons']);
  let allKeys = await new GpgParser(gpgOutput.stdout);
  return allKeys.filter((key) => {
    return ['marginal', 'full', 'ultimate'].includes(key.trust);
  }).map((key) => {
    return key.fingerprint;
  });
}

getTrustedKeyFingerprints().then((keys) => {
  console.log('Trusted keys', keys);
}).catch((e) => {
  console.log('Error', e);
});

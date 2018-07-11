function GpgKeyListParser(streamToConsume) {
  this.inputBuffer = Buffer.from('');
  return new Promise((resolve) => {
    streamToConsume.on('data', (data) => {
      this.bufferStream(data);
    });
    streamToConsume.on('finish', () => {
      resolve(this.processBuffer());
    });
  });
}

GpgKeyListParser.prototype.bufferStream = function(data) {
  this.inputBuffer = Buffer.concat([this.inputBuffer, data]);
};

GpgKeyListParser.prototype.processBuffer = function() {
  let bufferArray = this.inputBuffer.toString().trim().split('\n');
  let jsonOutput = [];
  let lineNumber = 0;
  let publicKeyObject;

  for (let line of bufferArray) {
    let lineArray = line.split(':');
    if (lineArray[0] === 'pub') {
      if (publicKeyObject) {
        jsonOutput.push(publicKeyObject);
      }
      publicKeyObject = lineArrayToObject('pub', lineArray);
    } else if (lineArray[0] === 'fpr') {
      if (publicKeyObject.subKeys && publicKeyObject.subKeys.length) {
        publicKeyObject.subKeys[publicKeyObject.subKeys.length - 1].fingerprint = lineArrayToObject('fpr', lineArray);
      } else {
        publicKeyObject.fingerprint = lineArrayToObject('fpr', lineArray);
      }
    } else if (lineArray[0] === 'uid') {
      publicKeyObject.userIds.push(lineArrayToObject('uid', lineArray));
    } else if (lineArray[0] === 'sub') {
      publicKeyObject.subKeys.push(lineArrayToObject('sub', lineArray));
    } else if (lineArray[0] === 'uat') {
      publicKeyObject.userAttributes.push(lineArrayToObject('uat', lineArray));
    } else if (lineArray[0] === 'rev') {
      publicKeyObject.signatures.push(lineArrayToObject('rev', lineArray));
    } else if (lineArray[0] === 'sig') {
      if (publicKeyObject.subKeys && publicKeyObject.subKeys.length) {
        publicKeyObject.subKeys[publicKeyObject.subKeys.length - 1].signatures.push(lineArrayToObject('sig', lineArray));
      } else {
        publicKeyObject.signatures.push(lineArrayToObject('sig', lineArray));
      }
    } else if (lineArray[0] === 'tru') {
      // Do nothing for trustDb entries
    } else {
      console.error(`Line type ${lineArray[0]} not yet supported, skipping line ${lineNumber}`);
    }
    lineNumber++;
  }

  return jsonOutput;
};

function lineArrayToObject(type, lineArray) {
  let lineObject = {
    longKeyId: lineArray[4],
    created: lineArray[5],
    expires: lineArray[6] || false
  };

  if (lineArray[11]) {
    lineObject.keyCapabilities = {
      encrypt: lineArray[11].includes('e') || lineArray[11].includes('E'),
      sign: lineArray[11].includes('s') || lineArray[11].includes('S'),
      certify: lineArray[11].includes('c') || lineArray[11].includes('C'),
      authentication: lineArray[11].includes('a') || lineArray[11].includes('A'),
      disabled: lineArray[11].includes('D'),
      additionalUnknownCapabilities: lineArray[11].includes('?')
    };
  }

  if (['sub', 'pub', 'uid'].includes(type)) {
    switch (lineArray[1]) {
      case 'u':
        lineObject.trust = 'ultimate';
        break;
      case 'f':
        lineObject.trust = 'full';
        break;
      case 'm':
        lineObject.trust = 'marginal';
        break;
      case 'n':
        lineObject.trust = 'never';
        break;
      case 'r':
        lineObject.trust = 'revoked';
        break;
      case 'e':
      case 'q':
      case '-':
        lineObject.trust = 'unknown';
        break;
    }
    // lineObject.trust = lineArray[1];
  }
  if (['sub', 'pub'].includes(type)) {
    lineObject.bits = parseInt(lineArray[2]);
    lineObject.signatures = [];
  }

  // Type-specific columns
  if (type === 'crt') {
    lineObject.serialNumber = lineArray[7];
  } else if (type === 'uid') {
    lineObject.uidHash = lineArray[7];
    lineObject.userId = lineArray[9];
  } else if (type === 'uat') {
    lineObject.uidHash = lineArray[7];
  } else if (type === 'pub') {
    lineObject.userIds = [];
    lineObject.subKeys = [];
    lineObject.userAttributes = [];
  } else if (type === 'fpr') {
    // Basically nothing else useful in FPR records
    lineObject = lineArray[9];
  } else if (['rev','sig'].includes(type)) {
    lineObject.userId = lineArray[9];
    if (lineArray[10]) {
      if (lineArray[10].includes('10')) {
        lineObject.signatureClass = 'unknown';
      } else if (lineArray[10].includes('11')) {
        lineObject.signatureClass = 'none';
      } else if (lineArray[10].includes('12')) {
        lineObject.signatureClass = 'some';
      } else if (lineArray[10].includes('13')) {
        lineObject.signatureClass = 'full';
      } else if (lineArray[10].includes('18')) {
        lineObject.signatureClass = 'owner';
      } else if (lineArray[10].includes('20')) {
        lineObject.signatureClass = 'revoked';
      } else if (lineArray[10].includes('28')) {
        lineObject.signatureClass = 'revoked';
      } else if (lineArray[10].includes('30')) {
        lineObject.signatureClass = 'revoked';
      } else {
        // We don't understand whatever class this is so just write actual value
        lineObject.signatureClass = lineArray[10];
      }
    }
  }

  return lineObject;
}

module.exports = GpgKeyListParser;

// If run directly rather than required we automatically read stdin and write to stdout
if (require.main === module) {
  new GpgKeyListParser(process.stdin).then((jsonOutput) => {
    console.log(JSON.stringify(jsonOutput, null, 2));
  }).catch((err) => {
    console.log('Error', err);
  });
}

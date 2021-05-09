# CasperLabs SDK for JavaScript

## Installation

```bash
# Basic Node.JS installation
npm install casper-client-sdk --save
```

## Documentation

Documentation generated from code is available [here](https://casper-ecosystem.github.io/casper-client-sdk/)

## Tests

```
npm run test
```

## Examples

### Working with keys

```
import { Keys, PublicKey } from "casper-client-sdk";

// generate new keys
const { publicKey, privateKey } = Keys.Ed25519.new();
// get account-address from public key
const accountAddress = publicKey.toAccountHex();
// Get account-hash (Uint8Array) from public key
const accountAddress = publicKey.toAccountHash();

// store keys as PEM files
const publicKeyInPem = edKeyPair.exportPublicKeyInPem();
const privateKeyInPem = edKeyPair.exportPrivateKeyInPem();

// you can then recreate public key from stored account-address
const recreatedPublicKey = PublicKey.from(accountAddress);
// ...and convert it accordingly.
```

### Sending transfer

```
// RPC_API can be obtained from cspr.live/tools/peers
const casperClient = new CasperClient(RPC_API);
const address = account_address;

const folder = path.join('./', 'casper_keys');
const signKeyPair = Keys.Ed25519.parseKeyFiles(
    folder + '/' + address + '_public.pem',
    folder + '/' + address + '_private.pem'
  );

// chainspec_name can be obtained from //API:8888 json response
const networkName = chainspec_name;

// for native-transfers payment price is fixed
const paymentAmount = 10000000000;
// minimal amount is 2.5CSPR so 2.5 * 10.000 (1CSPR = 10.000 motes)
const transferAmount = amount;
// transfer_id field in the request to tag the transaction and to correlate it to your back-end storage
const id = 187821;

const deployParams = new DeployUtil.DeployParams(
  signKeyPair.publicKey,
  networkName
);

const toAddr = PublicKey.fromHex(to);

const session = DeployUtil.ExecutableDeployItem.newTransfer(
  transferAmount,
  toAddr,
  undefined,
  id
);

const payment = DeployUtil.standardPayment(paymentAmount);
const deploy = DeployUtil.makeDeploy(deployParams, session, payment);
const signedDeploy = DeployUtil.signDeploy(deploy, signKeyPair);


// in deploy succeed you will get deploy-hash
const result = await casperClient.putDeploy(signedDeploy);
```

More examples of library usage are stored inside `/test` directory.

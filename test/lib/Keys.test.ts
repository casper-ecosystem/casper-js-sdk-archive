import { expect } from 'chai';
import { decodeBase16, decodeBase64, DeployUtil, encodeBase16 } from '../../src';
import { Ed25519, Secp256K1 } from '../../src/lib/Keys';
import { byteHash } from '../../src/lib/Contracts';
import * as nacl from 'tweetnacl-ts';
import { encodeBase64 } from 'tweetnacl-ts';

import * as fs from 'fs';
import * as Crypto from 'crypto';
import * as path from 'path';
import * as os from 'os';
import { CasperHDKey } from '../../src/lib/CasperHDKey';

describe('Ed25519', () => {
  it('calculates the account hash', () => {
    const signKeyPair = Ed25519.new();
    // use lower case for node-rs
    const name = Buffer.from('ED25519'.toLowerCase());
    const sep = decodeBase16('00');
    const bytes = Buffer.concat([
      name,
      sep,
      signKeyPair.publicKey.rawPublicKey
    ]);
    const hash = byteHash(bytes);

    expect(Ed25519.accountHash(signKeyPair.publicKey.rawPublicKey)).deep.equal(
      hash
    );
  });

  it('should generate PEM file for Ed25519 correctly', () => {
    const naclKeyPair = Ed25519.new();
    const publicKeyInPem = naclKeyPair.exportPublicKeyInPem();
    const privateKeyInPem = naclKeyPair.exportPrivateKeyInPem();

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'test-'));
    fs.writeFileSync(tempDir + '/public.pem', publicKeyInPem);
    fs.writeFileSync(tempDir + '/private.pem', privateKeyInPem);
    const signKeyPair2 = Ed25519.parseKeyFiles(
      tempDir + '/public.pem',
      tempDir + '/private.pem'
    );

    // expect nacl could import the generated PEM
    expect(encodeBase64(naclKeyPair.publicKey.rawPublicKey)).to.equal(
      encodeBase64(signKeyPair2.publicKey.rawPublicKey)
    );
    expect(encodeBase64(naclKeyPair.privateKey)).to.equal(
      encodeBase64(signKeyPair2.privateKey)
    );

    // import pem file to nodejs std library
    const pubKeyImported = Crypto.createPublicKey(publicKeyInPem);
    const priKeyImported = Crypto.createPrivateKey(privateKeyInPem);
    expect(pubKeyImported.asymmetricKeyType).to.equal('ed25519');

    // expect nodejs std lib export the same pem.
    const publicKeyInPemFromNode = pubKeyImported.export({
      type: 'spki',
      format: 'pem'
    });
    const privateKeyInPemFromNode = priKeyImported.export({
      type: 'pkcs8',
      format: 'pem'
    });
    expect(publicKeyInPemFromNode).to.equal(publicKeyInPem);
    expect(privateKeyInPemFromNode).to.equal(privateKeyInPem);

    // expect both of they generate the same signature
    const message = Buffer.from('hello world');
    const signatureByNode = Crypto.sign(null, message, priKeyImported);
    const signatureByNacl = nacl.sign_detached(
      Buffer.from(message),
      naclKeyPair.privateKey
    );
    expect(encodeBase64(signatureByNode)).to.eq(encodeBase64(signatureByNacl));

    // expect both of they could verify by their own public key
    expect(Crypto.verify(null, message, pubKeyImported, signatureByNode)).to
      .true;
    expect(
      nacl.sign_detached_verify(
        message,
        signatureByNacl,
        naclKeyPair.publicKey.rawPublicKey
      )
    ).to.true;
  });

  it('should deal with different line-endings', () => {
    const keyWithoutPem =
      'MCowBQYDK2VwAyEA4PFXL2NuakBv3l7yrDg65HaYQtxKR+SCRTDI+lXBoM8=';
    const key1 = decodeBase64(keyWithoutPem);
    const keyWithLF =
      '-----BEGIN PUBLIC KEY-----\n' +
      'MCowBQYDK2VwAyEA4PFXL2NuakBv3l7yrDg65HaYQtxKR+SCRTDI+lXBoM8=\n' +
      '-----END PUBLIC KEY-----\n';
    const key2 = Ed25519.readBase64WithPEM(keyWithLF);
    expect(key2).to.deep.eq(key1);
    const keyWithCRLF =
      '-----BEGIN PUBLIC KEY-----\r\n' +
      'MCowBQYDK2VwAyEA4PFXL2NuakBv3l7yrDg65HaYQtxKR+SCRTDI+lXBoM8=\r\n' +
      '-----END PUBLIC KEY-----\r\n';
    const key3 = Ed25519.readBase64WithPEM(keyWithCRLF);
    expect(key3).to.deep.eq(key1);
  });
});

describe('Secp256K1', () => {
  it('calculates the account hash', async () => {
    const signKeyPair = await Secp256K1.new();
    // use lower case for node-rs
    const name = Buffer.from('secp256k1'.toLowerCase());
    const sep = decodeBase16('00');
    const bytes = Buffer.concat([
      name,
      sep,
      signKeyPair.publicKey.rawPublicKey
    ]);
    const hash = byteHash(bytes);

    expect(
      Secp256K1.accountHash(signKeyPair.publicKey.rawPublicKey)
    ).deep.equal(hash);
  });

  it('should generate PEM file for Secp256K1 correctly', async () => {
    const signKeyPair = await Secp256K1.new();

    // export key in pem to save
    const publicKeyInPem = signKeyPair.exportPublicKeyInPem();
    const privateKeyInPem = signKeyPair.exportPrivateKeyInPem();

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'test-'));
    fs.writeFileSync(tempDir + '/public.pem', publicKeyInPem);
    fs.writeFileSync(tempDir + '/private.pem', privateKeyInPem);

    // expect importing keys from pem files works well
    expect(Secp256K1.parsePublicKeyFile(tempDir + '/public.pem')).to.deep.eq(
      signKeyPair.publicKey.rawPublicKey
    );
    expect(Secp256K1.parsePrivateKeyFile(tempDir + '/private.pem')).to.deep.eq(
      signKeyPair.privateKey
    );

    const signKeyPair2 = Secp256K1.parseKeyFiles(
      tempDir + '/public.pem',
      tempDir + '/private.pem'
    );

    // expect parseKeyFiles could import files
    expect(encodeBase64(signKeyPair.publicKey.rawPublicKey)).to.equal(
      encodeBase64(signKeyPair2.publicKey.rawPublicKey)
    );
    expect(encodeBase64(signKeyPair.privateKey)).to.equal(
      encodeBase64(signKeyPair2.privateKey)
    );

    // import pem file to nodejs std library
    const ecdh = Crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(signKeyPair.privateKey);
    expect(ecdh.getPublicKey('hex', 'compressed')).to.deep.equal(
      encodeBase16(signKeyPair.publicKey.rawPublicKey)
    );

    // expect we could sign the message and verify the signature later.
    const message = Buffer.from('hello world');
    const signature = signKeyPair.sign(Buffer.from(message));
    // expect we could verify the signature created by ourself
    expect(signKeyPair.verify(signature, message)).to.equal(true);
  });

  it('Test Ledger vector 1', () => {
    let seed = Buffer.from("ed2f664e65b5ef0dd907ae15a2788cfc98e41970bc9fcb46f5900f6919862075e721f37212304a56505dab99b001cc8907ef093b7c5016a46b50c01cc3ec1cac", "hex");
    let master = CasperHDKey.fromMasterSeed(seed);
    let keyPair = master.deriveIndex(0);

    let json = {
      "deploy": {
        "hash": "a155d0bc8ae2089079b3dd155e1d6597a4a705bca3154aaafcf28fc693e40a31",
        "header": {
          "account": "02028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297",
          "timestamp": "2021-06-08T13:40:22.846Z",
          "ttl": "30m",
          "gas_price": 1,
          "body_hash": "f7859590eee1a88b04ec76ecf17e24093df4a8bea6ce247bac5a965cee6d9bca",
          "dependencies": [],
          "chain_name": "casper-test"
        },
        "payment": {
          "ModuleBytes": {
            "module_bytes": "",
            "args": [
              ["amount", {
                "cl_type": "U512",
                "bytes": "0600a0724e1809",
                "parsed": "null"
              }]
            ]
          }
        },
        "session": {
          "Transfer": {
            "args": [
              ["amount", {
                "cl_type": "U512",
                "bytes": "0500f2052a01",
                "parsed": "null"
              }],
              ["target", {
                "cl_type": {
                  "ByteArray": 32
                },
                "bytes": "e5d30118dc4e254d29250296f0cbcfbae17263a3c7f745b55aabee62f5f06eb1",
                "parsed": "null"
              }],
              ["id", {
                "cl_type": {
                  "Option": "U64"
                },
                "bytes": "013930000000000000",
                "parsed": "null"
              }]
            ]
          }
        },
        "approvals": []
      }
    };

    let expected = {
      "signer": "02028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297",
      "signature": "02748582748c3082a522f8660e88f25634a9889cf9175b35a02428534005f188f61f491479210fd61a952b647a406709b331c996b2c27336ce0cb8f66d7ea063ec"
    };

    let deploy = DeployUtil.deployFromJson(json)!;

    let signed_deploy = DeployUtil.signDeploy(deploy, keyPair);
    
    let signer = signed_deploy.approvals[0].signer;
    expect(signer).to.equal(expected.signer);
    
    let signature = signed_deploy.approvals[0].signature;
    expect(signature).to.equal(expected.signature);
  });

  it('Test Ledger vector 2', () => {
    let seed = Buffer.from("ed2f664e65b5ef0dd907ae15a2788cfc98e41970bc9fcb46f5900f6919862075e721f37212304a56505dab99b001cc8907ef093b7c5016a46b50c01cc3ec1cac", "hex");
    let master = CasperHDKey.fromMasterSeed(seed);
    let keyPair = master.deriveIndex(0);

    let json = {
        "deploy": {
          "hash": "2682bd51fc51c3295ff0ba9bb07d055d39aa895bbf88a25c26d87b219ade1b6d",
          "header": {
            "account": "02028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297",
            "timestamp": "2021-06-09T09:50:47.135Z",
            "ttl": "30m",
            "gas_price": 1,
            "body_hash": "f7859590eee1a88b04ec76ecf17e24093df4a8bea6ce247bac5a965cee6d9bca",
            "dependencies": [],
            "chain_name": "casper-test"
          },
          "payment": {
            "ModuleBytes": {
              "module_bytes": "",
              "args": [
                [
                  "amount",
                  {
                    "cl_type": "U512",
                    "bytes": "0600a0724e1809",
                    "parsed": "null"
                  }
                ]
              ]
            }
          },
          "session": {
            "Transfer": {
              "args": [
                [
                  "amount",
                  {
                    "cl_type": "U512",
                    "bytes": "0500f2052a01",
                    "parsed": "null"
                  }
                ],
                [
                  "target",
                  {
                    "cl_type": {
                      "ByteArray": 32
                    },
                    "bytes": "e5d30118dc4e254d29250296f0cbcfbae17263a3c7f745b55aabee62f5f06eb1",
                    "parsed": "null"
                  }
                ],
                [
                  "id",
                  {
                    "cl_type": {
                      "Option": "U64"
                    },
                    "bytes": "013930000000000000",
                    "parsed": "null"
                  }
                ]
              ]
            }
          },
          "approvals": []
        }
    };

    let expected = {
      "signer": "02028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297",
      "signature": "025e4d63590cd77d612bbda45af01a98553e02809d89117460a8411f0cd85490c62a9ec853fffdf9f714f472a7c0f60a91f97960d4de81841d9cc482ea676a9b22"
    };

    let deploy = DeployUtil.deployFromJson(json)!;

    let signed_deploy = DeployUtil.signDeploy(deploy, keyPair);
    
    let signer = signed_deploy.approvals[0].signer;
    expect(signer).to.equal(expected.signer);
    
    let signature = signed_deploy.approvals[0].signature;
    expect(signature).to.equal(expected.signature);
  });
});

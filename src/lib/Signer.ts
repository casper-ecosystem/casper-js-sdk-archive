/**
 * Provide methods to communicate with [CasperLabs Signer Extension](https://github.com/CasperLabs/signer).
 * Works only on browser.
 *
 * @packageDocumentation
 */

import { DeployUtil, PublicKey } from ".";
import { Deploy } from "./DeployUtil";

/**
 * Check whether CasperLabs Signer extension is connected
 */
export const isConnected: () => Promise<boolean> = async () => {
  return await window.casperlabsHelper!.isConnected();
};

/**
 * Attempt connection to Signer
 */
export const sendConnectionRequest: () => void = () => {
  return window.casperlabsHelper!.requestConnection();
};

/**
 * Return base64 encoded public key of user current selected account.
 *
 * @throws Error if haven't connected to CasperLabs Signer browser extension.
 */
export const getSelectedPublicKeyBase64: () => Promise<string> = () => {
  return window.casperlabsHelper!.getSelectedPublicKeyBase64();
};

/**
 * Retrieve the active public key.
 *
 * @returns {string} Hex-encoded public key with algorithm prefix.
 */
export const getActivePublicKey: () => Promise<PublicKey> = () => {
  return window.casperlabsHelper!.getActivePublicKey().then(publicKeyHex => {
    return PublicKey.fromHex(publicKeyHex);
  });
};

/**
 * Send deploy to plugin to sign.
 *
 * @param deploy the deploy that plugin received to sign.
 * @param publicKey the public key used to sign the deploy, if set, we will check whether it is the same as the active key for signing the message.
 *
 * @throws Error if haven't connected to CasperLabs Signer browser extension.
 * @throws Error if publicKey is not the same as the key that Signer used to sign the message.
 */
export const sign: (
  deploy: Deploy,
  publicKey: PublicKey
) => Promise<string> = (deploy: Deploy, publicKey: PublicKey) => {
  return window.casperlabsHelper!.sign(
    DeployUtil.deployToJson(deploy),
    publicKey.toAccountHex()
  );
};

/*
 * Forces Signer to disconnect from the currently open site.
 */
export const disconnectFromSite: () => void = () => {
  return window.casperlabsHelper!.disconnectFromSite();
};

export const forceConnection: () => void = () => {
  return window.signerTestingHelper!.forceConnection();
};

export const forceDisconnect: () => void = () => {
  return window.signerTestingHelper!.forceDisconnect();
};

export const hasCreatedVault: () => Promise<boolean> = () => {
  return window.signerTestingHelper!.hasCreatedVault();
};

export const resetExistingVault: () => Promise<void> = () => {
  return window.signerTestingHelper!.resetExistingVault();
};

export const createNewVault: (password: string) => Promise<void> = (
  password: string
) => {
  return window.signerTestingHelper!.createNewVault(password);
};

export const createTestAccount: (
  name: string,
  privateKey: string
) => Promise<void> = (name: string, privateKey: string) => {
  return window.signerTestingHelper!.createTestAccount(name, privateKey);
};

export const getToSignMessageID: () => Promise<number | null> = () => {
  return window.signerTestingHelper!.getToSignMessageID();
};

export const signTestDeploy: (msgId: number) => Promise<void> = (
  msgId: number
) => {
  return window.signerTestingHelper!.signTestDeploy(msgId);
};

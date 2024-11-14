// Encryption to the Future
// This class initializes the ETF.js SDK
//
// see: https://polkadot.js.org/docs/api/FAQ/#since-upgrading-to-the-7x-series-typescript-augmentation-is-missing
import '@polkadot/api-augment'
import { ApiPromise, WsProvider } from '@polkadot/api'
import { ScProvider } from '@polkadot/rpc-provider'
import * as Sc from '@substrate/connect'
import { BN, BN_ONE, hexToString, hexToU8a } from "@polkadot/util";
import init, { build_encoded_commitment, tle, tld, decrypt } from 'tle-wasm-wrapper'
import hkdf from 'js-crypto-hkdf'; // for npm
import { Pulse, Justfication } from './types'

/**
 * Encryption to the Future
 * This class initializes the ETF.js SDK
 */
export class Etf {
  public ibePubkey: any
  public isProd: boolean
  public api!: ApiPromise
  private providerMultiAddr: string
  private readonly MAX_CALL_WEIGHT2 = new BN(1_000_000_000_000).isub(BN_ONE);
  private readonly MAX_CALL_WEIGHT = new BN(5_000_000_000_000).isub(BN_ONE);
  private readonly PROOFSIZE = new BN(1_000_000_000);
  private readonly HASH = 'SHA-256';
  private readonly HASHLENGTH = 32;

  /**
   * Constructor for the etf api
   * @param providerMultiAddr (optional): The multiaddress of an RPC node
   * e.g. insecure local node:    ws://localhost:9944 
   *      secure websocket (rpc): wss://etf1.idealabs.network:443
   */
  constructor(
    providerMultiAddr?: string,
    isProd?: boolean,
  ) {
    this.providerMultiAddr = providerMultiAddr
    this.isProd = isProd
  }

  /**
   * Connect to the chain and start etf api wrapper
   * @param chainSpec The ETF Network (raw) chain spec
   */
  async init(
    chainSpec?: string,
    extraTypes?: any
  ): Promise<void> {
    let provider
    if (this.providerMultiAddr == undefined) {
      let spec = JSON.stringify(chainSpec)
      provider = new ScProvider(Sc, spec)
      await provider.connect()
    } else {
      provider = new WsProvider(this.providerMultiAddr)
    }

    this.api = await ApiPromise.create({
      provider,
      types: {
        ...extraTypes, Pulse
      }
    })
    await init();
    await this.api.isReady

    this.ibePubkey = await this.api.query.etf.roundPublic()
    console.log('api is ready')
  }

  /**
   * A proxy to the polkadotjs api type registry creation
   */
  createType(typeName: string, typeData: any): any {
    return this.api.registry.createType(typeName, typeData);
  }

  /**
   * listens for incoming justifications and invokes the callback when new ones are streamed
   * @param callback: a callback to handle the new justifications
   */
  subscribeBeacon(callback: any): void {
    this.api.rpc.beefy.subscribeJustifications((sig) => {
      callback(new Justfication(sig.toHuman()["V1"]))
    })
  }

  /**
   * Query a pulse from runtime storage, could be empty
   * @param blockNumber: The block number of the pulse you want returned
   * @returns: Pulse of randomness
   */
  async getPulse(blockNumber): Promise<Pulse> {
    return this.api.query.randomnessBeacon.pulses(blockNumber).then(pulse => {
      return new Pulse(
        blockNumber,
        pulse.toHuman()['body'].randomness,
        pulse.toHuman()['body'].signature
      );
    });
  }

  /**
   * Timelock Encryption: Encrypt the message for the given block
   * @param message: The message to encrypt
   * @param blockNumber: The block number when the message unlocks
   * @param seed: A seed to derive crypto keys
   * @returns the ciphertext
   */
  timelockEncrypt(encodedMessage: Uint8Array, blockNumber: number, seed: string): Promise<any> {
    // TODO: fine for now but should ultimately query the BABE pallet config instead
    // let epochLength = 200;
    // let validatorSetId = blockNumber % epochLength;
    let t = new TextEncoder();
    let masterSecret = t.encode(seed);
    return hkdf.compute(masterSecret, this.HASH, this.HASHLENGTH, '').then((derivedKey) => {
      let commitment = build_encoded_commitment(blockNumber, 0);
      // let encodedMessage = t.encode(message);
      // let encodedMessage = message;
      let ct = tle(commitment, encodedMessage, derivedKey.key, this.ibePubkey)
      return ct;
    });
  }

  /**
   * Timelock decryption: Decrypt the ciphertext using a pulse from the beacon produced at the given block
   * @param ciphertext: Ciphertext to be decrypted
   * @param blockNumber: Block number that has the signature for decryption
   * @returns: Plaintext of encrypted message
   */
  timelockDecrypt(ciphertext, blockNumber): Promise<any> {
    return this.getPulse(blockNumber).then(pulse => {
      let sig: Uint8Array = hexToU8a(pulse.signature);
      return tld(ciphertext, sig);
    });
  }

  /**
   * Decrypt a ciphertext early if you know the seed
   * @param ciphertext The ciphertext to decrypt
   * @param seed The ciphertext seed
   * @returns The plaintext
   */
  async decrypt(ciphertext, seed): Promise<any> {
    let t = new TextEncoder();
    let masterSecret = t.encode(seed);
    return hkdf.compute(masterSecret, this.HASH, this.HASHLENGTH, '').then((derivedKey) => {
      let pt = decrypt(ciphertext, derivedKey);
      return pt;
    });
  }

  /**
   * Prepare a secure delayed transaction for a given deadline.
   * 
   * ex:
   * etf.delay(
   *  api.tx.balances
   *    .transferKeepAlive(BOB, 100), 477382)
   *    .signAndSend(alice, result => {...})
   * 
   * @param rawCall: The call to delay
   * @param priority: The call priority
   * @param blockNumber: The block for which the call should be executed
   * @returns (call, sk, block) where the call is a call to schedule the delayed transaction
   */
  async delay(rawCall, priority, blockNumber, seed): Promise<any> {
    try {
      let call = this.createType('Call', rawCall);
      let out = await this.timelockEncrypt(call.toU8a(), blockNumber, seed);
      return this.api.tx.scheduler.scheduleSealed(blockNumber, priority, out);
    } catch (e) {
      throw e;
    }
  }
}

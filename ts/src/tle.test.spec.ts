import { describe, expect } from '@jest/globals'
import { Etf } from './tle'
import { ApiPromise } from '@polkadot/api'

import chainSpec from './test/etfTestSpecRaw.json';

describe('Etf', () => {
  // let emitter;
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    // emitter = new EventEmitter();
  })

  afterEach(() => {
    jest.clearAllTimers();
  });

  it('should initialize correctly', async () => {
    const createSpy = jest.spyOn(ApiPromise, 'create')
    const etf = new Etf('ws://localhost:9944')
    await etf.init(JSON.stringify(chainSpec))
    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: expect.anything(),
      })
    )
    createSpy.mockRestore()
  })

  it('should initialize correctly with light client', async () => {
    const createSpy = jest.spyOn(ApiPromise, 'create')
    const etf = new Etf()
    await etf.init(JSON.stringify(chainSpec))
    expect(createSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: expect.anything(),
      })
    )
    createSpy.mockRestore()
  })

  it('should call subscribeJustifications callback every 30 seconds with BeaconSim pulse', async () => {
    const mockCallback = jest.fn();
    const etf = new Etf('wss://example.com', true);

    await etf.init();

    etf.subscribeBeacon(mockCallback);

    // Fast-forward 3 seconds
    jest.advanceTimersByTime(3000);
    expect(mockCallback).toHaveBeenCalledTimes(1);
    expect(mockCallback).toHaveBeenCalledWith(expect.objectContaining({
      signaturesCompact: expect.any(Array) // Assuming signature is a string
    }));

    // Fast-forward another 3 seconds
    jest.advanceTimersByTime(3000);
    expect(mockCallback).toHaveBeenCalledTimes(2);
    expect(mockCallback).toHaveBeenCalledWith(expect.objectContaining({
      signaturesCompact: expect.any(Array)
    }));

    // Fast-forward another 3 seconds
    jest.advanceTimersByTime(3000);
    expect(mockCallback).toHaveBeenCalledTimes(3);
    expect(mockCallback).toHaveBeenCalledWith(expect.objectContaining({
      signaturesCompact: expect.any(Array)
    }));
  });

  it('should call getPulse', async () => {
    const etf = new Etf('wss://example.com', true);
    await etf.init()

    etf.getPulse(0).then(pulse => {
      expect(pulse.randomness).toBe('0x1001001100100110011010101');
      expect(pulse.round).toBe(0);
      expect(pulse.signature).toBe('coleman <3 UwO');
    });
  });

  it('should timelock encrypt a message', async () => {
    const etf = new Etf()
    await etf.init(JSON.stringify(chainSpec), false)
    const seed = 'seed';
    const latestBlockNumber = 123;
    const message = 'Hello, world!'
    await etf.timelockEncrypt(new TextEncoder().encode(message), latestBlockNumber, seed).then((result) => {
      let result_string = JSON.stringify(result);
      let expected_string = JSON.stringify({
        aes_ct: { ciphertext: [ 0 ], nonce: [ 1 ] },
        etf_ct: 'mocked-etf-ct',
        sk: [
          0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 1
        ]
      });
      expect(result_string).toBe(expected_string);
    });
  })

  it('should timelock decrypt a message', async () => {
    const etf = new Etf()
    await etf.init(JSON.stringify(chainSpec), false)
    const blockNumber = 1;
    const ciphertext = 'ciphertext'
    const result = await etf.timelockDecrypt(ciphertext, blockNumber);
    expect(result).toEqual({
      message: 'mocked-decrypted',
      sk: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    })
  })

  it('should decrypt a message on demand if the user knows the secret', async () => {
    const etf = new Etf()
    await etf.init(JSON.stringify(chainSpec), false)
    const secret = "shhh, it's a secret";
    const ciphertext = 'ciphertext'
    const result = await etf.decrypt(ciphertext, secret);
    expect(result).toEqual({
      message: 'mocked-decrypted',
      sk: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    })
  })
  
})

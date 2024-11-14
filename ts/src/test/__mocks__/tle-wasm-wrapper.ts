// __mocks__/@ideallabs/tle-wasm-wrapper.ts

// Mocked implementation of init
export default async function init() {
  // Mock initialization logic
}

// Mocked implementation of tle encrypt function
export function tle(message_bytes, slot_id_bytes, t) {
  return {
    aes_ct: {
      ciphertext: [0],
      nonce: [1],
    },
    etf_ct: 'mocked-etf-ct',
    sk: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]
  }
}

// Mocked implementation of tle decrypt function
export function tld(ciphertext, justification) {
  return {
    message: 'mocked-decrypted',
    sk: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]
  }
}

// Mocked implementation of tle decrypt function
export function decrypt(ciphertext, secretKey) {
  return {
    message: 'mocked-decrypted',
    sk: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]
  }
}
 
// Mocked implementation of tle build_encoded_commitment function
export function build_encoded_commitment(blockNumber, validator_set_id) {
  let t = new TextEncoder();
  let commitment = {
    "payload": "0x1101001001110110001001010011110010010101010110",
    "block_number": 32,
    "validator_set_id": "IDs for Validators"
  
  };
  let commitment_string = JSON.stringify(commitment);
  // let encoded_commitment = t.encode(commitment_string);
  return commitment_string;
}

export function extract_signature(id, sk) {
  return parseInt(id + sk);
}
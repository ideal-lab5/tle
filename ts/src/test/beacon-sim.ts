  export class Pulse{
    
    public commitment: string
    public signaturesFrom: string
    public validatorSetLen: number
    public signaturesCompact: [string]

    constructor(commitment, signaturesFrom, validatorSetLen, signaturesCompact) {
        this.commitment = commitment;
        this.signaturesFrom = signaturesFrom;
        this.validatorSetLen = validatorSetLen;
        this.signaturesCompact = signaturesCompact;
    }
  }
  
  export class BeaconSim {
    public chainId: any
    public keypair: any
    public prevPulseIndex: any

    constructor(chainId, keypair, genesis) {
      this.chainId = chainId;
      this.keypair = keypair;
      this.prevPulseIndex = genesis;
    }
  
    nextPulse() {
      let pulse = new Pulse("commitment", "signaturesFrom", 1, ["sigs"]);
      return pulse;
    }
  }
/* global BigInt */
import React, { useEffect, useState } from 'react'
import { Etf } from '@ideallabs/etf.js'
import './App.css'

import { Keyring } from '@polkadot/api';
import { ContractPromise } from '@polkadot/api-contract';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import { SHA3 } from 'sha3';
import { BN, BN_ONE } from "@polkadot/util";

import chainSpec from './resources/etfTestSpecRaw.json';
import contractMetadata from './resources/proxy/tlock_proxy.json';

import { web3Accounts, web3Enable, web3FromAddress } from '@polkadot/extension-dapp';

import { PROXY_CONTRACT_ADDR } from './constants.js';

function App() {

  const MAX_CALL_WEIGHT2 = new BN(1_000_000_000_000).isub(BN_ONE);
  const MAX_CALL_WEIGHT = new BN(5_000_000_000_000).isub(BN_ONE);
  const PROOFSIZE = new BN(1_000_000_000);
  const [api, setApi] = useState(null);
  const [alice, setAlice] = useState(null);

  const [contract, setContract] = useState(null);
  const [auctionContractId, setAuctionContractId] = useState('');
  const [auctionReady, setAuctionReady] = useState(false);
  const [latestSlot, setLatestSlot] = useState(0)

  const [deadline, setDeadline] = useState(0);

  // custom types for the auction structs
  const CustomTypes = {
    Proposal: {
      ciphertext: 'Vec<u8>',
      nonce: 'Vec<u8>',
      capsule: 'Vec<u8>',
      commitment: 'Vec<u8>',
    },
    AuctionResult: {
      winner: 'AccountId',
      debt: 'Balance'
    }
  };

  useEffect(() => {
    const setup = async () => {
      await cryptoWaitReady()
      // let api = new Etf('ws://3.136.13.113:9944')
      let api = new Etf('wss://etf1.idealabs.network:443')
      await api.init(chainSpec, CustomTypes)
      setApi(api);
      const keyring = new Keyring()
      // load the proxy contract
      const contract = new ContractPromise(
        api.api, 
        contractMetadata, 
        PROXY_CONTRACT_ADDR
      )
      setContract(contract)
      // const allInjected = await web3Enable('etf-auction-example');
      // const allAccounts = await web3Accounts();
      // finds an injector for an address
      // const injector = await web3FromAddress(SENDER);
      const alice = keyring.addFromUri('//Alice', { name: 'Alice' }, 'sr25519')
      setAlice(alice)
    }
    setup()
  }, [])
  
  // useEffect(() => {
  //   if (api !== null)
  //     api.eventEmitter.on('blockHeader', () => {
  //       setLatestSlot(api.latestSlot.slot)
  //     })
  // }, [api])

  const newAuction = async(name, assetId, deadline, deposit) => {
     // now we want to call the publish function of the contract
     // call the publish function of the contract
     await contract.tx
       .newAuction({
         gasLimit: api.api.registry.createType('WeightV2', {
           refTime: MAX_CALL_WEIGHT2,
           proofSize: PROOFSIZE,
         }),
         storageDepositLimit: null,
       },
        name, 
        assetId, 
        deadline, 
        deposit,
       ).signAndSend(alice, result => {
         if (result.status.isInBlock) {
          // console.log(result.toHuman().Ok)
          console.log('auction created');
         } else if (result.status.isFinalized) {
           console.log('finalized');
         }
       });
 
  }

  const loadAuction = async(accountId) => {
    const storageDepositLimit = null
    const { gasRequired, storageDeposit, result, output } = 
      await contract.query.getAuctionDetails(
      alice.address,
      {
        gasLimit: api?.registry.createType('WeightV2', {
          refTime: MAX_CALL_WEIGHT,
          proofSize: PROOFSIZE,
        }),
        storageDepositLimit,
      },
      accountId,
    );
    setDeadline(output.toHuman().Ok.Ok.deadline.replaceAll(",", ""))
    setAuctionReady(true)
    setAuctionContractId(accountId)
  }

  const proposeBid = async() => {
    // e.preventDefault()
    // we do not want to bind the message to the state
    const inputElement = document.getElementById('bid')
    const hasher = new SHA3(256)
    hasher.update(inputElement.value)
    const hash = hasher.digest();
    // the seed shouldn't be reused 
    let timelockedBid = api.encrypt(inputElement.value, 1, [deadline], "testing234");
    console.log(timelockedBid)
    // now we want to call the publish function of the contract
    const value = 1000000;
    // call the publish function of the contract
    await contract.tx
      .bid({
        gasLimit: api.api.registry.createType('WeightV2', {
          refTime: MAX_CALL_WEIGHT2,
          proofSize: PROOFSIZE,
        }),
        storageDepositLimit: null,
        value: value,
      },
        auctionContractId,
        timelockedBid.ct.aes_ct.ciphertext,
        timelockedBid.ct.aes_ct.nonce,
        timelockedBid.ct.etf_ct[0],
        Array.from(hash),
      ).signAndSend(alice, result => {
        if (result.status.isInBlock) {
          console.log('in a block');
          console.log(result.toHuman().Ok);
        } else if (result.status.isFinalized) {
          console.log('finalized');
        }
      });
  }

  const doComplete = async () => {
    let revealedBids = await revealBids()
    console.log(revealedBids)

    await contract.tx
      .complete({
        gasLimit: api.api.registry.createType('WeightV2', {
          refTime: new BN(1_290_000_000_000),
          proofSize: new BN(5_000_000_000_000),
        }),
        storageDepositLimit: null,
      },
        auctionContractId,
        revealedBids
      ).signAndSend(alice, result => {
        if (result.isErr) {
          const errorMsg = result.toJSON();
          console.log(errorMsg)
        }
        if (result.status.isInBlock) {
          console.log('in a block');
          console.log(result.toHuman());
        } else if (result.status.isFinalized) {
          console.log('finalized');
        }
      });
  }

  /// fetch ciphertext from currently loaded auction contract
  /// and decrypt each
  ///
  /// returns an array of (AccountId, Proposal)
  const revealBids = async () => {
    // fetch ciphertexts from the appropriate auction contract and decrypt them
    const storageDepositLimit = null
    const { gasRequired, storageDeposit, result, output } = 
      await contract.query.getEncryptedBids(
      alice.address,
      {
        gasLimit: api?.registry.createType('WeightV2', {
          refTime: MAX_CALL_WEIGHT,
          proofSize: PROOFSIZE,
        }),
        storageDepositLimit,
      },
      auctionContractId,
    );
    if (!result.err) {
      let revealedBids = []
      let cts = output.toHuman().Ok.Ok;
      for (const c of cts) {
        let bidder = c[0];
        let proposal = api.createType('Proposal', c[1])
        console.log(proposal)
        let plaintext = await api.decrypt(
          proposal.ciphertext,
          proposal.nonce,
          [proposal.capsule], 
          [deadline],
        )
        let bid = Number.parseInt(String.fromCharCode(...plaintext))
        let revealedBid = {
          bidder: api.createType('AccountId', bidder), 
          bid: bid,
        }
        revealedBids.push(revealedBid)
      }
      return revealedBids
    }
    
    return []
  }

  const getWinner = async () => {
    const storageDepositLimit = null
    const { gasRequired, storageDeposit, result, output } = 
      await contract.query.getWinner(
      alice.address,
      {
        gasLimit: api?.registry.createType('WeightV2', {
          refTime: MAX_CALL_WEIGHT,
          proofSize: PROOFSIZE,
        }),
        storageDepositLimit,
      },
      auctionContractId,
    );
    return api.createType('AuctionResult', result).toHuman()
    // return api.createType('AuctionResult', result.toHuman().Ok.Ok)
  }

  const doClaim = async () => {
    // call get winner
    let result = await getWinner()
    // if you're the winner, send the debt
    let value = alice.address === result.winner ? result.debt : 0

    await contract.tx
      .claim({
        gasLimit: api.api.registry.createType('WeightV2', {
          refTime: new BN(1_290_000_000_000),
          proofSize: new BN(5_000_000_000_000),
        }),
        storageDepositLimit: null,
        value: value,
      },
        auctionContractId,
      ).signAndSend(alice, result => {
        if (result.isErr) {
          const errorMsg = result.toJSON();
          console.log(errorMsg)
        }
        if (result.status.isInBlock) {
          console.log('in a block');
          console.log(result.toHuman());
        } else if (result.status.isFinalized) {
          console.log('finalized');
        }
      });
  }

  const CreateAuctionForm = () => {
    const [name, setName] = useState('');
    const [deadline, setDeadline] = useState(0);
    const [assetId, setAssetId] = useState(0);
    const [deposit, setDeposit] = useState(0);

    return (
      <div>
        <h1>Create Auction</h1>
        <div className='form'>
          <input type="text" placeholder='name' onChange={(e) => {e.preventDefault();setName(e.target.value)}} />
          <input type="number" placeholder='deadline' onChange={(e) => setDeadline(e.target.value)} />
          <input type="number" placeholder='assetId' onChange={(e) => setAssetId(e.target.value)} />
          <div>
            <input type="number" placeholder='deposit' onChange={(e) => setDeposit(e.target.value)} /> ETF
          </div>
          <button onClick={() => newAuction(
            name, assetId, deadline, deposit
          )}>Deploy</button>
        </div>
      </div>
    );
  }

  return (
    <div className="App">
      <div className="header">
        Etf Auction Contract Example
      </div>
      {/* <div>
      <span>Latest Slot: </span>
      <span>{ latestSlot }</span>
      </div> */}
      <div className="body">
        <div>
          <CreateAuctionForm />
        </div>
        { auctionReady === false ? 
        <div>
          <h1>Search Auctions</h1>
          <span>Enter an auction contract account id</span>
          <div>
            <input type="text" placeholder='5gx621a4...' onChange={(e) => setAuctionContractId(e.target.value)} />
            <button onClick={() => loadAuction(auctionContractId)}>Load Auction</button>
          </div>
        </div> :
        <div>
          <div>
            <input type='number' placeholder='100' id='bid' /> Unit
          </div>
          <button onClick={proposeBid}>Propose Bid</button>
          <button onClick={async () => await doComplete()}>Complete Auction</button>
          <button onClick={doClaim}>Claim Auction Prize</button>
        </div>
        }
        {/* <button onClick={doComplete}>Complete Auction</button> */}
      </div>
    </div>
  )
}

export default App

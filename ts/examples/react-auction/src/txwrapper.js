
//   /**
//    * Builds a signed tx
//    * @param {*} api 
//    * @param {*} alice 
//    * @param {*} amount 
//    * @returns 
//    */
//   const build_transaction = async (api, alice, amount) => {
//     let blockHash = await api.api.query.system.blockHash(api.latestBlockNumber)
//     let genesisHash = await api.api.query.system.blockHash(0)

//     let unsigned =
//       create_unsigned_tx(
//         alice, contractAddr,
//         buildBidData(amount),
//         api.latestBlockNumber,
//         blockHash,
//         genesisHash,
//         registry,
//         metadataRpc,
//         transactionVersion,
//         specVersion
//       )

//     let signed = create_signed_tx(
//       alice, unsigned, registry, metadataRpc
//     );
//     return signed;
//   }

//   /**
//    * 
//    * See: Ethereum forwarding contract
//    * 
//    * Creates an unsigned transaction
//    * @param {*} alice 
//    * @param {*} dest 
//    * @param {*} data 
//    * @param {*} blockNumber 
//    * @param {*} blockHash 
//    * @param {*} genesisHash 
//    * @param {*} registry 
//    * @param {*} metadataRpc 
//    * @param {*} transactionVersion 
//    * @param {*} specVersion 
//    * @returns 
//    */
//   const create_unsigned_tx = (
//     alice, dest, data, blockNumber, blockHash, genesisHash, registry, metadataRpc, transactionVersion, specVersion,
//   ) => {
//     console.log(data);
//     const unsigned = methods.contracts.call(
//       {
//         dest: { id: dest },
//         value: 1,
//         gasLimit: {
//           "refTime": 0, // how to estimate?
//           "proofSize": 0,
//         },
//         storageDepositLimit: 900719920,
//         data: data
//       },
//       {
//         address: deriveAddress(alice.publicKey, 42), // TODO, use correct prefix
//         blockHash,
//         blockNumber: registry
//           .createType('BlockNumber', blockNumber)
//           .toNumber(),
//         eraPeriod: 64,
//         genesisHash,
//         metadataRpc,
//         nonce: 0, // Assuming this is Alice's first tx on the chain Q: how can we get the right nonce?
//         specVersion,
//         tip: 0,
//         transactionVersion,
//       },
//       {
//         metadataRpc,
//         registry,
//       }
//     )
//     return unsigned
//   }

//   /**
//    * Signs an unsigned transaction
//    * @param {*} alice 
//    * @param {*} unsigned 
//    * @param {*} registry 
//    * @param {*} metadataRpc 
//    * @returns 
//    */
//   const create_signed_tx = (alice, unsigned, registry, metadataRpc) => {
//     // Construct the signing payload from an unsigned transaction.
//     const signingPayload = construct.signingPayload(unsigned, { registry });
//     console.log(`\nPayload to Sign: ${signingPayload}`);

//     // Decode the information from a signing payload.
//     const payloadInfo = decode(signingPayload, {
//       metadataRpc,
//       registry,
//     })
//     console.log(
//       // TODO all the log messages need to be updated to be relevant to the method used
//       `\nDecoded Transaction\n  To: ${payloadInfo.method.args.dest}\n` +
//       `  Amount: ${payloadInfo.method.args.value}`
//     )

//     // Sign a payload. This operation should be performed on an offline device.
//     const signature = signWith(alice, signingPayload, {
//       metadataRpc,
//       registry,
//     });
//     console.log(`\nSignature: ${signature}`);

//     // Encode a signed transaction.
//     const tx = construct.signedTx(unsigned, signature, {
//       metadataRpc,
//       registry,
//     });
//     console.log(`\nTransaction to Submit: ${tx}`);
//     return tx;
//   }

//   const buildBidData = (amount) => {
//     let t = new TextEncoder();
//     let callData = '';
//     // append the select
//     callData += blake2AsHex('bid').substring(0, 4)
//     // append the args
//     callData += t.encode(amount).toString().replaceAll(",", "")
//     return callData
//   }

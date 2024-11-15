# Etf Futures Example

This is an example of interacting with a futures contract on the ETF network.

The flow is like this:

- prepare a signed transaction to a contract using @ideallabs/txwrapper-etf
- use etf to encrypt for slots specified by a contract
- publish the encrypted tx
- complete an auction and select a winner
- execute all bids

## Installation

From this directory, run:

```bash
npm i && npm run start
```
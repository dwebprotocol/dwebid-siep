# @dwebid/simple-identity-exchange-protocol
A protocol for exchanging diffKeys and a seed to an identity document (multi-writer dTree), between one device and another.

### Install
```
npm install @dwebid/simple-identity-exchange-protocol
```

## Usage On Device A
```js
import SIEP from '@dwebid/simple-identity-exchange-protocol'

let seed = null
let remoteDiffKey = null

// true means Device A is the initiator
const a = new SIEP(true, {
  // make sure the connection with Device B is encrypted and that there is a NOISE handshake
  encrypted: true
  noise: true
  // listen for the handshake to finalize and react to it
  onhandshake() {
    a.open(1, { deviceId: keyHere })
  }
  // listen for a verify message and react to it.
  onverify (channel, message) {
     // retrieve type from message
    const verificationType = message.type
    if (verificationType === "device-verification") {
      // send the secret shown on the screen of Device B
      a.prove(channel, { secret: 777777 })
    }
  }
  // listen for a releaseseed message and react to it.
  onreleaseseed (channel, message) {
    // Extract seed from message sent by Device B
    seed = message.seed
  }
  // listen for a wantkey message and react to it.
  onwantkey (channel, message) {
    // save Device A's dTree diffKey into a constant
    const dMessengerDbDiffKey = db.diffKey
    // provide the key that Device B asked for in their `wantkey` message
    a.provideKey(channel, {
      identifier: "dmessenger",
      diffKey: dMessengerDbDiffKey
    })    
  }
  // listen for a providekey message and react to it
  onprovidekey (channel, message) {
    // Extract the diffKey from the message sent by Device B
    remoteDiffKey = message.diffKey
  }
})
```

## Usage On Device B
```
import SIEP from '@dwebid/simple-identity-exchange-protocol'

let seed = null
let remoteDiffKey = nulll
let verified = false

// false means Device B is the receiver
const b = new SIEP(false, {
   // make sure the connection to Device A is encrypted
  encrypted: true
   // listen for an open message and react to it
  onopen (channel, message) {
    console.log(`Connection opened with deviceID ${message.deviceId} on channel # ${channel}`)
    // when Device A opens the connection, we send a verify message immediately back to device A, letting it
    // know which type of verification is required.
    b.verify(channel, { type: 'device-verification' })
  }
  // listen for a "prove" message and react to it
  onproof (channel, message) {
    const secretCode = 777777
    // ensure that the secret code sent in the prove message, is the secretCode Device B is expecting.
    if (message.secret ==== secretCode) {
      verified = true
      seed = secretEncryptionSeedHere
      // since Device A verified the secret, we can now release the seed
      b.releaseseed(channel, { seed: seed })
     // while we're at it, lets ask Device B for their diffKey for the database related to "dmessenger"
      b.wantkey(channel, { identifier: 'dmessenger' })
    } else {
      b.destroy()
    }
  }
  // listen for a providekey message and react to it
  onprovidekey (channel, message) {
    remoteDiffKey = message.diffKey
  }
  // listen for a wantkey message and react to it
  onwantkey (channel, message) {
    if (verified) {
      b.providekey(channel, { identifier: 'dmessenger', diffKey: db.diffKey })
    }
  }
})
```

## API Documentation
Coming soon

## LICENSE 
[MIT](LICENSE.md)
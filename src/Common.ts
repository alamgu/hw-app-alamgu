/********************************************************************************
 *   Ledger Node JS API
 *   (c) 2016-2017 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
import type Transport from "@ledgerhq/hw-transport";
import sha256 from "fast-sha256";

export type GetPublicKeyResult = {
  publicKey: string;
};
export type SignTransactionResult = {
  signature: string;
};
export type GetVersionResult = {
  major: number;
  minor: number;
  patch: number;
};

/**
 * Common API for ledger apps
 *
 * @example
 * import Kadena from "hw-app-kda";
 * const kda = new Kadena(transport)
 */

export class Common {
  transport: Transport;
  appName: string | null;

  constructor(transport: Transport, scrambleKey: string, appName: string | null = null) {
    this.transport = transport;
    this.appName = appName;
    transport.decorateAppAPIMethods(
      this,
      ["menu", "getPublicKey", "signTransaction", "getVersion"],
      "KDA"
    );
  }

  /**
    * Retrieves the public key associated with a particular BIP32 path from the ledger app.
    *
    * @param path - the path to retrieve.
    */
  async getPublicKey(
    path: string,
  ): Promise<GetPublicKeyResult> {
    const cla = 0x00;
    const ins = 0x02;
    const p1 = 0;
    const p2 = 0;
    const payload = buildBip32KeyPayload(path);
    const response = await this.sendChunks(cla, ins, p1, p2, payload);
    const responseSize = response[0];
    const publicKey = response.slice(1, responseSize+1); // slice uses end index.
    const res: GetPublicKeyResult = {
      publicKey: publicKey.toString("hex"),
    };
    return res;
  }

  /**
    * Sign a transaction with the key at a BIP32 path.
    *
    * @param txn - The transaction; this can be any of a node Buffer, Uint8Array, or a hexadecimal string, encoding the form of the transaction appropriate for hashing and signing.
    * @param path - the path to use when signing the transaction.
    */
  async signTransaction(
    path: string,
    txn: string | Buffer | Uint8Array,
  ): Promise<SignTransactionResult> {
    const paths = splitPath(path);
    const cla = 0x00;
    const ins = 0x03;
    const p1 = 0;
    const p2 = 0;
    // Transaction payload is the byte length as uint32le followed by the bytes
    // Type guard not actually required but TypeScript can't tell that.
    const rawTxn = typeof txn == "string" ? Buffer.from(txn, "hex") : Buffer.from(txn);
    const hashSize = Buffer.alloc(4);
    hashSize.writeUInt32LE(rawTxn.length, 0);
    // Bip32key payload same as getPublicKey
    const bip32KeyPayload = buildBip32KeyPayload(path);
    // These are just squashed together
    const payload = Buffer.concat([hashSize, rawTxn, bip32KeyPayload])
    // TODO batch this since the payload length can be uint32le.max long
    const response = await this.sendChunks(cla, ins, p1, p2, payload);
    // TODO check this
    const signature = response.slice(0,-2).toString("hex");
    return {
      signature,
    };
  }

  /**
    * Retrieve the app version on the attached ledger device.
    * @alpha TODO this doesn't exist yet
    */

  async getVersion(): Promise<GetVersionResult> {
    const [major, minor, patch, ...appName] = await this.transport.send(
      0x00,
      0x00,
      0x00,
      0x00,
      Buffer.alloc(0)
    );
    return {
      major,
      minor,
      patch
    };
  }
  
  /**
   * Send a raw payload as chunks to a particular APDU instruction.
   *
   * @remarks
   *
   * This is intended to be used to implement a more useful API in this class and subclasses of it, not for end use.
   */
  async sendChunks(
    cla: number,
    ins: number,
    p1: number,
    p2: number,
    payload: Buffer
  ): Promise<Buffer> {
    let rv;
    let chunkSize=230;
    for(let i=0;i<payload.length;i+=chunkSize) {
      rv = await this.transport.send(cla, ins, p1, p2, payload.slice(i, i+chunkSize));
    }
    return rv;
  }


  async sendWithBlocks(
    cla: number,
    ins: number,
    p1: number,
    p2: number,
    payload: Buffer,
    extraData: Map<Buffer, Buffer> = new Map<Buffer, Buffer>()
  ): Promise<Buffer> {
    let rv;
    let chunkSize=180;
    let chunkList : Buffer[] = [];
    for(let i=0; i<payload.length; i+=chunkSize) {
      let cur = payload.slice(i, i+chunkSize);
      chunkList.push(cur);
    }
    let lastHash = Buffer.alloc(32);
    let data = chunkList.reduceRight((blocks, chunk) => {
      let linkedChunk = Buffer.concat([lastHash, chunk]);
      lastHash = Buffer.from(sha256(linkedChunk));
      blocks.set(lastHash, chunk);
      return blocks;
    }, new Map<Uint8Array, Buffer>(extraData));
    return await this.handleBlocksProtocol(cla, ins, p1, p2, Buffer.concat([Buffer.from([HostToLedger.START]), lastHash]), data);
  }

  async handleBlocksProtocol(
    cla: number,
    ins: number,
    p1: number,
    p2: number,
    initialPayload: Buffer,
    data: Map<Uint8Array, Buffer>
  ): Promise<Buffer> {
    let payload = initialPayload;
    let result = new Buffer(0);
    do {
      let rv = await this.transport.send(cla, ins, p1, p2, payload);
      var rv_instruction = rv[0];
      let rv_payload = rv.slice(1);
      if ( ! (rv_instruction in LedgerToHost) ) {
        throw new TypeError("Unknown instruction returned from ledger");
      }
      switch(rv_instruction) {
        case LedgerToHost.RESULT_ACCUMULATING:
        case LedgerToHost.RESULT_FINAL:
          result = Buffer.concat([result, rv_payload]);
          // Won't actually send this if we drop out of the loop for RESULT_FINAL
          payload = Buffer.from([HostToLedger.RESULT_ACCUMULATING_RESPONSE]);
          break;
        case LedgerToHost.GET_CHUNK:
          let chunk = data.get(rv_payload);
          if( chunk ) {
            payload = Buffer.concat([Buffer.from([HostToLedger.GET_CHUNK_RESPONSE_SUCCESS]), chunk]);
          } else {
            payload = Buffer.from([HostToLedger.GET_CHUNK_RESPONSE_FAILURE]);
          }
          break;
        case LedgerToHost.PUT_CHUNK:
          data.set(Buffer.from(sha256(rv_payload)), rv_payload);
          payload = Buffer.from([HostToLedger.PUT_CHUNK_RESPONSE]);
          break;
      }
    } while (rv_instruction != 1);
    return result;
  }
}

enum LedgerToHost {
  RESULT_ACCUMULATING = 0,
    RESULT_FINAL = 1,
    GET_CHUNK = 2,
    PUT_CHUNK = 3
};

enum HostToLedger {
  START = 0,
    GET_CHUNK_RESPONSE_SUCCESS = 1,
    GET_CHUNK_RESPONSE_FAILURE = 2,
    PUT_CHUNK_RESPONSE = 3,
    RESULT_ACCUMULATING_RESPONSE = 4
};

function buildBip32KeyPayload(path: string): Buffer {
  const paths = splitPath(path);
  // Bip32Key payload is:
  // 1 byte with number of elements in u32 array path
  // Followed by the u32 array itself
  const payload = Buffer.alloc(1 + paths.length * 4);
  payload[0] = paths.length
  paths.forEach((element, index) => {
    payload.writeUInt32LE(element, 1 + 4 * index);
  });
  return payload
}

// TODO use bip32-path library
function splitPath(path: string): number[] {
  const result: number[] = [];
  const components = path.split("/");
  components.forEach((element) => {
    let number = parseInt(element, 10);

    if (isNaN(number)) {
      return; // FIXME shouldn't it throws instead?
    }

    if (element.length > 1 && element[element.length - 1] === "'") {
      number += 0x80000000;
    }

    result.push(number);
  });
  return result;
}

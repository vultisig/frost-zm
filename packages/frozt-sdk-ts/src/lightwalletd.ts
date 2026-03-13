import type { CompactBlock, CompactTx, CompactOutput, CompactSpend } from "./types.js";

export class LightwalletClient {
  private baseUrl: string;

  constructor(grpcWebUrl: string) {
    this.baseUrl = grpcWebUrl.replace(/\/$/, "");
  }

  async getLatestBlockHeight(): Promise<number> {
    const response = await this.unaryCall(
      "cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock",
      new Uint8Array(0), // ChainSpec (empty)
    );
    return readBlockHeight(response);
  }

  async getBlockRange(startHeight: number, endHeight: number): Promise<CompactBlock[]> {
    const request = encodeBlockRange(startHeight, endHeight);
    const responses = await this.serverStreamCall(
      "cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange",
      request,
    );
    return responses.map(parseCompactBlock);
  }

  async getTransaction(txHash: Uint8Array): Promise<Uint8Array> {
    // TxFilter: field 3 = hash (bytes)
    const buf: number[] = [0x1a, txHash.length, ...txHash];
    const response = await this.unaryCall(
      "cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTransaction",
      new Uint8Array(buf),
    );
    // RawTransaction: field 1 = data (bytes), field 2 = height (varint)
    return parseRawTransactionData(response);
  }

  async getTreeState(height: number): Promise<string> {
    const request = encodeBlockId(height);
    const response = await this.unaryCall(
      "cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState",
      request,
    );
    return parseTreeStateSaplingTree(response);
  }

  private async unaryCall(method: string, body: Uint8Array): Promise<Uint8Array> {
    const frame = encodeGrpcWebFrame(body);
    const response = await fetch(`${this.baseUrl}/${method}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/grpc-web+proto",
        "X-Grpc-Web": "1",
      },
      body: frame as unknown as BodyInit,
    });

    if (!response.ok) {
      throw new Error(`gRPC-web error: ${response.status} ${response.statusText}`);
    }

    const responseBytes = new Uint8Array(await response.arrayBuffer());
    const frames = decodeGrpcWebFrames(responseBytes);
    if (frames.length === 0) {
      throw new Error("empty gRPC-web response");
    }
    return frames[0];
  }

  private async serverStreamCall(method: string, body: Uint8Array): Promise<Uint8Array[]> {
    const frame = encodeGrpcWebFrame(body);
    const response = await fetch(`${this.baseUrl}/${method}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/grpc-web+proto",
        "X-Grpc-Web": "1",
      },
      body: frame as unknown as BodyInit,
    });

    if (!response.ok) {
      throw new Error(`gRPC-web error: ${response.status} ${response.statusText}`);
    }

    const responseBytes = new Uint8Array(await response.arrayBuffer());
    return decodeGrpcWebFrames(responseBytes);
  }
}

function encodeGrpcWebFrame(data: Uint8Array): Uint8Array {
  const frame = new Uint8Array(5 + data.length);
  frame[0] = 0; // no compression
  frame[1] = (data.length >> 24) & 0xff;
  frame[2] = (data.length >> 16) & 0xff;
  frame[3] = (data.length >> 8) & 0xff;
  frame[4] = data.length & 0xff;
  frame.set(data, 5);
  return frame;
}

function decodeGrpcWebFrames(data: Uint8Array): Uint8Array[] {
  const frames: Uint8Array[] = [];
  let offset = 0;
  while (offset < data.length) {
    if (offset + 5 > data.length) break;
    const flag = data[offset];
    const length =
      (data[offset + 1] << 24) |
      (data[offset + 2] << 16) |
      (data[offset + 3] << 8) |
      data[offset + 4];
    offset += 5;
    if (offset + length > data.length) break;
    if (flag === 0) {
      frames.push(data.slice(offset, offset + length));
    }
    // flag === 0x80 is trailers, skip
    offset += length;
  }
  return frames;
}

// Minimal protobuf encoding for BlockRange
function encodeBlockRange(startHeight: number, endHeight: number): Uint8Array {
  const startBlock = encodeBlockId(startHeight);
  const endBlock = encodeBlockId(endHeight);

  const buf: number[] = [];
  // field 1: BlockID start (length-delimited)
  buf.push(0x0a, startBlock.length, ...startBlock);
  // field 2: BlockID end (length-delimited)
  buf.push(0x12, endBlock.length, ...endBlock);
  return new Uint8Array(buf);
}

function encodeBlockId(height: number): Uint8Array {
  const buf: number[] = [];
  // field 1: height (varint)
  buf.push(0x08, ...encodeVarint(height));
  return new Uint8Array(buf);
}

function encodeVarint(value: number): number[] {
  const bytes: number[] = [];
  while (value > 0x7f) {
    bytes.push((value & 0x7f) | 0x80);
    value >>>= 7;
  }
  bytes.push(value & 0x7f);
  return bytes;
}

function readBlockHeight(data: Uint8Array): number {
  let offset = 0;
  while (offset < data.length) {
    const tag = data[offset++];
    const fieldNumber = tag >> 3;
    const wireType = tag & 0x07;

    if (fieldNumber === 1 && wireType === 0) {
      return readVarint(data, offset).value;
    }
    // skip other fields
    if (wireType === 0) {
      readVarint(data, offset);
      offset = readVarint(data, offset).nextOffset;
    } else if (wireType === 2) {
      const len = readVarint(data, offset);
      offset = len.nextOffset + len.value;
    }
  }
  return 0;
}

function readVarint(data: Uint8Array, offset: number): { value: number; nextOffset: number } {
  let value = 0;
  let shift = 0;
  while (offset < data.length) {
    const byte = data[offset++];
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return { value, nextOffset: offset };
}

function parseCompactBlock(data: Uint8Array): CompactBlock {
  let height = 0;
  const transactions: CompactTx[] = [];
  let offset = 0;

  while (offset < data.length) {
    const tag = data[offset++];
    const fieldNumber = tag >> 3;
    const wireType = tag & 0x07;

    if (wireType === 0) {
      const v = readVarint(data, offset);
      if (fieldNumber === 1) height = v.value;
      offset = v.nextOffset;
    } else if (wireType === 2) {
      const len = readVarint(data, offset);
      offset = len.nextOffset;
      const fieldData = data.slice(offset, offset + len.value);
      if (fieldNumber === 4) {
        transactions.push(parseCompactTx(fieldData));
      }
      offset += len.value;
    } else {
      break;
    }
  }

  return { height, transactions };
}

function parseCompactTx(data: Uint8Array): CompactTx {
  let hash = new Uint8Array(0);
  const spends: CompactSpend[] = [];
  const outputs: CompactOutput[] = [];
  let offset = 0;

  while (offset < data.length) {
    const tag = data[offset++];
    const fieldNumber = tag >> 3;
    const wireType = tag & 0x07;

    if (wireType === 0) {
      const v = readVarint(data, offset);
      offset = v.nextOffset;
    } else if (wireType === 2) {
      const len = readVarint(data, offset);
      offset = len.nextOffset;
      const fieldData = data.slice(offset, offset + len.value);

      if (fieldNumber === 2) hash = fieldData;
      else if (fieldNumber === 4) spends.push(parseCompactSpend(fieldData));
      else if (fieldNumber === 5) outputs.push(parseCompactOutput(fieldData));

      offset += len.value;
    } else {
      break;
    }
  }

  return { hash, spends, outputs };
}

function parseTreeStateSaplingTree(data: Uint8Array): string {
  let offset = 0;

  while (offset < data.length) {
    const tag = data[offset++];
    const fieldNumber = tag >> 3;
    const wireType = tag & 0x07;

    if (wireType === 0) {
      offset = readVarint(data, offset).nextOffset;
      continue;
    }

    if (wireType !== 2) {
      break;
    }

    const len = readVarint(data, offset);
    offset = len.nextOffset;
    const fieldData = data.slice(offset, offset + len.value);
    offset += len.value;

    if (fieldNumber === 5) {
      return new TextDecoder().decode(fieldData);
    }
  }

  throw new Error("TreeState response did not include saplingTree");
}

function parseCompactSpend(data: Uint8Array): CompactSpend {
  let nf = new Uint8Array(0);
  let offset = 0;

  while (offset < data.length) {
    const tag = data[offset++];
    const fieldNumber = tag >> 3;
    const wireType = tag & 0x07;

    if (wireType === 2) {
      const len = readVarint(data, offset);
      offset = len.nextOffset;
      if (fieldNumber === 1) nf = data.slice(offset, offset + len.value);
      offset += len.value;
    } else if (wireType === 0) {
      const v = readVarint(data, offset);
      offset = v.nextOffset;
    } else {
      break;
    }
  }

  return { nf };
}

function parseCompactOutput(data: Uint8Array): CompactOutput {
  let cmu = new Uint8Array(0);
  let ephemeralKey = new Uint8Array(0);
  let ciphertext = new Uint8Array(0);
  let offset = 0;

  while (offset < data.length) {
    const tag = data[offset++];
    const fieldNumber = tag >> 3;
    const wireType = tag & 0x07;

    if (wireType === 2) {
      const len = readVarint(data, offset);
      offset = len.nextOffset;
      const fieldData = data.slice(offset, offset + len.value);

      if (fieldNumber === 1) cmu = fieldData;
      else if (fieldNumber === 2) ephemeralKey = fieldData;
      else if (fieldNumber === 3) ciphertext = fieldData;

      offset += len.value;
    } else if (wireType === 0) {
      const v = readVarint(data, offset);
      offset = v.nextOffset;
    } else {
      break;
    }
  }

  return { cmu, ephemeralKey, ciphertext };
}

function parseRawTransactionData(data: Uint8Array): Uint8Array {
  let offset = 0;
  while (offset < data.length) {
    const tag = data[offset++];
    const fieldNumber = tag >> 3;
    const wireType = tag & 0x07;

    if (wireType === 2) {
      const len = readVarint(data, offset);
      offset = len.nextOffset;
      if (fieldNumber === 1) {
        return data.slice(offset, offset + len.value);
      }
      offset += len.value;
    } else if (wireType === 0) {
      const v = readVarint(data, offset);
      offset = v.nextOffset;
    } else {
      break;
    }
  }
  return new Uint8Array(0);
}

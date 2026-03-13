export class MoneroRpcClient {
  private url: string;

  constructor(daemonUrl: string) {
    this.url = daemonUrl.replace(/\/$/, "");
  }

  async getHeight(): Promise<number> {
    const resp = await this.jsonRpc("get_block_count", {});
    return resp.count;
  }

  async isKeyImageSpent(keyImages: string[]): Promise<boolean[]> {
    const resp = await fetch(`${this.url}/is_key_image_spent`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key_images: keyImages }),
    });
    if (!resp.ok) throw new Error(`RPC error: ${resp.status}`);
    const data = await resp.json() as { spent_status: number[] };
    return data.spent_status.map((s: number) => s !== 0);
  }

  private async jsonRpc(method: string, params: Record<string, unknown>): Promise<Record<string, number>> {
    const resp = await fetch(`${this.url}/json_rpc`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: "0", method, params }),
    });
    if (!resp.ok) throw new Error(`RPC error: ${resp.status}`);
    const data = await resp.json() as { result: Record<string, number> };
    return data.result;
  }
}

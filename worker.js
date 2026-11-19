export default {
  async fetch(request, env) {
    const url = new URL(request.url);


    // Health check
    if (request.method === "GET" && url.pathname === "/") {
      return Response.json({
        service: "CHU Bingo Payo Worker",
        status: "running"
      });
    }

    // Payo webhook endpoint
    if (url.pathname === "/payo/callback") {
      if (request.method !== "POST") {
        return new Response("Method not allowed", {
          status: 405
        });
      }

      if (!env.env.PAYO_WEBHOOK_SECRET) {
        return new Response("Webhook secret missing", {
          status: 500
        });
      }

      const body = await request.text();
      const signature =
        request.headers.get("x-pygate-signature") || "";

      const match = signature.match(/^sha256=([a-f0-9]{64})$/i);

      if (!match) {
        return new Response("Invalid signature", {
          status: 401
        });
      }

      const encoder = new TextEncoder();

      const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(env.PAYO_API_KEY),
        {
          name: "HMAC",
          hash: "SHA-256"
        },
        false,
        ["sign"]
      );

      const digest = await crypto.subtle.sign(
        "HMAC",
        key,
        encoder.encode(body)
      );

      const expected = Array.from(new Uint8Array(digest))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");

      if (expected !== match[1].toLowerCase()) {
        return new Response("Signature verification failed", {
          status: 401
        });
      }

      let event;

      try {
        event = JSON.parse(body);
      } catch {
        return new Response("Invalid JSON", {
          status: 400
        });
      }

      if (!event.orderId || !event.status) {
        return new Response("Invalid payment event", {
          status: 400
        });
      }

      console.log("Verified Payo event:", {
        orderId: event.orderId,
        status: event.status,
        amount: event.amount,
        currency: event.currency
      });

      return Response.json({
        received: true,
        verified: true,
        walletUpdated: false
      });
    }

    return new Response("Not found", {
      status: 404
    });
  }
};

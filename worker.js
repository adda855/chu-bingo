
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

    // Payo callback
    if (url.pathname === "/payo/callback") {
      if (request.method !== "POST") {
        return new Response("Method not allowed", {
          status: 405
        });
      }

      const secret = env.PAYO_WEBHOOK_SECRET;

      if (!secret) {
        return new Response("Webhook secret missing", {
          status: 500
        });
      }

      const body = await request.text();

      const signature =
        request.headers.get("x-pygate-signature") || "";

      const match = signature.match(
        /^sha256=([a-f0-9]{64})$/i
      );

      if (!match) {
        return new Response("Invalid signature", {
          status: 401
        });
      }

      // Verify HMAC SHA-256 signature.
      // Confirm this algorithm and header with Payo's documentation.
      const encoder = new TextEncoder();

      const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(secret),
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

      const expected = Array.from(
        new Uint8Array(digest)
      )
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");

      const received = match[1].toLowerCase();

      if (expected !== received) {
        return new Response(
          "Signature verification failed",
          { status: 401 }
        );
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

      console.log("Verified Payo callback", {
        orderId: event.orderId,
        status: event.status
      });

      return Response.json({
        received: true,
        verified: true,
        walletUpdated: false,
        nextStep: "Server-side payment verification required"
      });
    }

    return new Response("Not found", {
      status: 404
    });
  }
};

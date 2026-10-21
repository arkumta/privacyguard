import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const source = typeof body.source === "string" ? body.source : "";
    const filename = typeof body.filename === "string" ? body.filename : "Contract.sol";

    if (!source.trim()) {
      return NextResponse.json({ detail: "Paste Solidity source code before scanning." }, { status: 400 });
    }
    if (Buffer.byteLength(source, "utf8") > 200_000) {
      return NextResponse.json({ detail: "Source is too large. Limit is 200 KB." }, { status: 413 });
    }

    const apiUrl = process.env.SCANNER_API_URL || "http://localhost:8000";
    const upstream = await fetch(`${apiUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source, filename }),
      cache: "no-store",
      signal: AbortSignal.timeout(60_000),
    });
    const data = await upstream.json();
    return NextResponse.json(data, { status: upstream.status });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scanner backend is unavailable.";
    return NextResponse.json(
      { detail: `Could not reach the local scanner backend. Make sure Docker Compose is running. ${message}` },
      { status: 502 }
    );
  }
}

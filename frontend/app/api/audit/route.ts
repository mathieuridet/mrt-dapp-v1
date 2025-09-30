import { NextResponse } from "next/server";
import { runAudit } from "@/lib/audit";

export async function POST(req: Request) {
  try {
    const { address } = await req.json();

    if (!address) {
      return NextResponse.json({ error: "Missing contract address" }, { status: 400 });
    }

    // Run your pipeline
    const report = await runAudit(address);

    return NextResponse.json({ report });
  } catch (err: unknown) {
    console.error("Audit error:", err);
    const message = err instanceof Error ? err.message : "Audit failed";
    
    return new Response(
      JSON.stringify({ error: message }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
}
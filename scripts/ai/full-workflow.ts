import path from "path";
import fs from "fs";
import fetch from "node-fetch";
import { execSync } from "child_process";
import dotenv from "dotenv";

dotenv.config();

const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY!;

type EtherscanResponse = {
  status: string;
  message: string;
  result: Array<{
    SourceCode: string;
    ContractName: string;
    CompilerVersion: string;
  }>;
};

async function fetchContractSource(address: string): Promise<string> {
  const url = `https://api-sepolia.etherscan.io/api?module=contract&action=getsourcecode&address=${address}&apikey=${ETHERSCAN_API_KEY}`;
  const res = await fetch(url);
  const data = (await res.json()) as EtherscanResponse;

  if (!data.result || !data.result[0].SourceCode) {
    throw new Error("No verified source found for this address.");
  }

  const rawSource = data.result[0].SourceCode;
  const contractName = data.result[0].ContractName;

  // Clean tmp folder
  fs.mkdirSync("./tmp", { recursive: true });

  // Case 1: Flattened single file (just Solidity)
  if (rawSource.trim().startsWith("pragma")) {
    const filePath = `./tmp/${contractName}.sol`;
    fs.writeFileSync(filePath, rawSource);
    return filePath;
  }

  // Case 2: JSON multi-file (wrapped with {{ ... }})
  if (rawSource.trim().startsWith("{{")) {
    // Remove outer curly braces
    const parsed = JSON.parse(rawSource.slice(1, -1));

    for (const [fileName, fileData] of Object.entries(parsed.sources)) {
      const outPath = path.join("./tmp", fileName);
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, (fileData as any).content);
    }

    // Return the *main* contract path
    return `./tmp/${contractName}.sol`;
  }

  throw new Error("Unknown SourceCode format returned by Etherscan");
}

async function runAudit(address: string) {
  console.log(`📥 Fetching source for ${address}...`);
  const contractPath = await fetchContractSource(address); // returns ./tmp/<something>.sol

  // --- Guard: if the file is actually JSON ({{ ... }} or { ... }), unpack all sources ---
  let entryPath = contractPath;
  const raw = fs.readFileSync(contractPath, "utf-8").trim();

  const tryParseEtherscanJson = (txt: string): any | null => {
    // double-brace format: {{ ... }}
    if (txt.startsWith("{{") && txt.endsWith("}}")) {
      try { return JSON.parse(txt.slice(1, -1)); } catch {}
    }
    // plain JSON: { ... }
    if (txt.startsWith("{") && txt.endsWith("}")) {
      try { return JSON.parse(txt); } catch {}
    }
    return null;
  };

  const srcJson = tryParseEtherscanJson(raw);

  if (srcJson && srcJson.sources) {
    // Clean tmp and re-create
    fs.rmSync("./tmp", { recursive: true, force: true });
    fs.mkdirSync("./tmp", { recursive: true });

    // Write all files exactly as referenced in the JSON
    for (const [fileName, fileData] of Object.entries(srcJson.sources as Record<string, { content: string }>)) {
      const outPath = path.join("./tmp", fileName);
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, (fileData as any).content, "utf-8");
    }

    // Prefer compiling the whole project so non-relative imports resolve from ./tmp
    entryPath = "./tmp"; // analyze the directory, not a single file
  } else {
    // Single-file source (or already-unpacked). Ensure tmp exists.
    fs.mkdirSync("./tmp", { recursive: true });
  }

  console.log("🔍 Running Slither...");
  // Important: run with cwd=./tmp so imports like "@openzeppelin/..." resolve to ./tmp/@openzeppelin/...
  // Output report one level up so it doesn't get wiped if we clean tmp later.
  if (fs.lstatSync(entryPath).isDirectory()) {
    execSync(`slither . --json ../slither-report.json`, {
      cwd: "./tmp",
      stdio: "inherit",
    });
  } else {
    // Single-file case: if imports use @openzeppelin/..., they must exist at project root.
    // Running from ./tmp still helps if the single file imports relative paths we wrote there.
    execSync(`slither ${path.basename(entryPath)} --json ../slither-report.json`, {
      cwd: path.dirname(entryPath),
      stdio: "inherit",
    });
  }

  console.log("📝 Running AI summarizer...");
  const reportRaw = fs.readFileSync("slither-report.json", "utf-8");
  const report = JSON.parse(reportRaw);

  const issues = (report?.results?.detectors ?? []).map((d: any) => ({
    check: d?.check,
    impact: d?.impact,
    confidence: d?.confidence,
    description: d?.description,
    elements: (d?.elements ?? []).map((e: any) => e?.name),
  }));

  const prompt = `
You are a Solidity security auditor.
Here are Slither findings for ${address}:
${JSON.stringify(issues, null, 2)}

Summarize in plain English:
- Group by severity (High/Medium/Low).
- Explain the risk.
- Provide practical remediation steps.
Format as Markdown.
`;

  const aiRes = await fetch("http://localhost:11434/api/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "mistral", prompt, stream: false }),
  });

  const data: any = await aiRes.json();
  fs.writeFileSync("audit-summary.md", data.response ?? "");
  console.log("✅ Audit complete: audit-summary.md");

  return data.response ?? "";
}


// Run from CLI
const address = process.argv[2];
if (!address) {
  console.error("Usage: ts-node run-audit.ts <contract-address>");
  process.exit(1);
}

runAudit(address);

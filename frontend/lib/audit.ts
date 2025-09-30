import path from "path";
import fs from "fs";
import fetch from "node-fetch";
import { execSync } from "child_process";
import swcData from "swc-registry/lib/swc-definition.json";

type SWCEntry = (typeof swcData)[keyof typeof swcData];

const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY!;
const TMP = './tmp';

export function getSWCEntry(id: string) {
  const entry = (swcData as Record<string, SWCEntry>)[id];
  if (!entry) return undefined;

  return {
    Id: id,
    markdown: entry.markdown,
    ...entry.content, // spread Title, Relationships, Description, Remediation
  };
}

type SlitherReport = {
  results?: {
    detectors?: DetectorResult[];
  };
};

type DetectorResult = {
  check: string;
  impact: string;
  confidence: string;
  description: string;
  elements?: DetectorElement[];
};

type DetectorElement = {
  name?: string;
  source_mapping?: {
    filename_relative?: string;
    lines?: number[];
  };
};

type EtherscanResponse = {
  status: string;
  message: string;
  result: Array<{
    SourceCode: string;
    ContractName: string;
    CompilerVersion: string;
  }>;
};

type OllamaResponse = {
  response?: string;
  error?: string;
};

type EtherscanMultiSource = {
  sources: Record<string, { content: string }>;
};

function getReferences(entry: import("swc-registry").EntryData): string[] {
  if (
    entry.Relationships &&
    typeof entry.Relationships !== "string" &&
    Array.isArray(entry.Relationships.References)
  ) {
    return entry.Relationships.References;
  }
  return [];
}

function enrichWithSWC(description: string) {
  const lower = description.toLowerCase();

  if (lower.includes("reentrancy")) return getSWCEntry("SWC-107");
  if (lower.includes("integer overflow")) return getSWCEntry("SWC-101");
  if (lower.includes("tx.origin")) return getSWCEntry("SWC-115");
  if (lower.includes("unchecked call")) return getSWCEntry("SWC-104");
  // … extend mapping as needed

  return null;
}

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
  fs.mkdirSync(TMP, { recursive: true });

  // Case 1: Flattened single file (just Solidity)
  if (rawSource.trim().startsWith("pragma")) {
    const filePath = path.join(TMP, `${contractName}.sol`);
    fs.writeFileSync(filePath, rawSource);
    return filePath;
  }

  // Case 2: JSON multi-file (wrapped with {{ ... }})
  if (rawSource.trim().startsWith("{{")) {
    const parsed = JSON.parse(rawSource.slice(1, -1)) as EtherscanMultiSource;

    for (const [fileName, fileData] of Object.entries(parsed.sources)) {
      const outPath = path.join(TMP, fileName); // preserves folder structure
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, fileData.content, "utf-8");
    }

    // Try to locate the main contract file dynamically
    const candidate = Object.keys(parsed.sources).find((fileName) =>
      fileName.endsWith(`${contractName}.sol`)
    );

    if (!candidate) {
      throw new Error(`Main contract ${contractName}.sol not found in sources`);
    }

    return path.join(TMP, candidate);
  }

  throw new Error("Unknown SourceCode format returned by Etherscan");
}

export async function runAudit(address: string) {
  console.log(`📥 Fetching source for ${address}...`);
  const contractPath = await fetchContractSource(address); // returns ./tmp/<something>.sol

  // --- Guard: if the file is actually JSON ({{ ... }} or { ... }), unpack all sources ---
  const raw = fs.readFileSync(contractPath, "utf-8").trim();

  const tryParseEtherscanJson = (txt: string): EtherscanMultiSource | null => {
    // double-brace format: {{ ... }}
    if (txt.startsWith("{{") && txt.endsWith("}}")) {
      try {
        return JSON.parse(txt.slice(1, -1)) as EtherscanMultiSource;
      } catch {
        return null;
      }
    }

    // plain JSON: { ... }
    if (txt.startsWith("{") && txt.endsWith("}")) {
      try {
        return JSON.parse(txt) as EtherscanMultiSource;
      } catch {
        return null;
      }
    }

    return null;
  };

  const srcJson = tryParseEtherscanJson(raw);

  if (srcJson && srcJson.sources) {
    // Clean tmp and re-create
    fs.rmSync(TMP, { recursive: true, force: true });
    fs.mkdirSync(TMP, { recursive: true });

    // Write all files exactly as referenced in the JSON
    for (const [fileName, fileData] of Object.entries(srcJson.sources as Record<string, { content: string }>)) {
      const outPath = path.join(TMP, fileName);
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, fileData.content, "utf-8");
    }
  } else {
    // Single-file source (or already-unpacked). Ensure tmp exists.
    fs.mkdirSync(TMP, { recursive: true });
  }

  console.log("🔍 Running Slither...");
  // Always run slither on ./tmp folder to include multiple files and/or imports
  execSync(`slither contracts --filter-paths @openzeppelin --json ../slither-report.json`, {
    cwd: "./tmp",
    stdio: "inherit",
  });

  console.log("📝 Running AI summarizer...");
  const reportRaw = fs.readFileSync("slither-report.json", "utf-8");
  const report = JSON.parse(reportRaw);

  const issues = (report as SlitherReport)?.results?.detectors?.map((d) => ({
    check: d.check,
    impact: d.impact,
    confidence: d.confidence,
    description: d.description,
    locations: (d.elements ?? []).map((e) => ({
      file: e.source_mapping?.filename_relative ?? "",
      line: e.source_mapping?.lines?.[0] ?? null,
      element: e.name ?? "",
    })),
  })) ?? [];

  if (issues.length === 0) {
    console.log("✅ No vulnerabilities found");
    return "✅ No vulnerabilities found by Slither for this contract.";
  }

  const enrichedIssues = issues.map((issue) => {
    const swcEntry = enrichWithSWC(issue.description ?? "");
    return {
      ...issue,
      swc: swcEntry
        ? {
            //id: swcEntry.Id,
            title: swcEntry.Title,
            remediation: swcEntry.Remediation,
            references: getReferences(swcEntry),
          }
        : null,
    };
  });

  const prompt = `
  You are a Solidity security auditor.

  Here are Slither findings for ${address}, enriched with SWC registry references:
  ${JSON.stringify(enrichedIssues, null, 2)}

  Summarize in plain English:
  - Group by severity
  - Explain risks
  - Suggest remediations (prefer SWC Remediation text if present)
  - Add references where relevant
  Format as Markdown.
  `;

  const aiRes = await fetch("http://localhost:11434/api/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "mistral", prompt, stream: false }),
  });

  const data = (await aiRes.json()) as OllamaResponse;
  fs.writeFileSync("audit-summary.md", data.response ?? "");
  console.log("✅ Audit complete: audit-summary.md");

  return data.response ?? "";
}

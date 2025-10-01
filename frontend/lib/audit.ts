/**
 * Audit pipeline (TypeScript, Node):
 * 1) Pull verified source from Etherscan (Sepolia API).
 * 2) Materialize a temp project with the contract sources.
 * 3) Run Slither and capture its JSON output (even on non-zero exit status).
 * 4) Normalize + enrich Slither issues with SWC references (where mapping is reliable).
 * 5) Option A: Deterministic Markdown renderer (no LLM).
 *    Option B: Constrained LLM renderer (validated; falls back to deterministic if it drifts).
 * 6) Write audit-summary.md and return the content.
 */

import path from "path";
import fs from "fs";
import { execSync, execFileSync } from "child_process";
import swcData from "swc-registry/lib/swc-definition.json";

// ────────────────────────────────────────────────────────────────────────────────
// Config
// ────────────────────────────────────────────────────────────────────────────────

/**
 * Etherscan API key must be set in the environment.
 * Note: This code calls the Sepolia API endpoint.
 */
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY!;

/** Working directory for materialized sources and Slither run */
const TMP = "./tmp";

// ────────────────────────────────────────────────────────────────────────────────
// Types (external JSON shapes + internal representations)
// ────────────────────────────────────────────────────────────────────────────────

type SWCEntry = (typeof swcData)[keyof typeof swcData];

type SlitherReport = {
  results?: {
    detectors?: DetectorResult[];
  };
};

type DetectorResult = {
  check: string;        // Slither check ID (e.g., "reentrancy-no-eth")
  impact: string;       // "High" | "Medium" | "Low" | "Informational"
  confidence: string;   // Slither confidence rating
  description: string;  // Slither’s human-readable summary (often includes locations)
  elements?: DetectorElement[]; // Raw location data
};

type DetectorElement = {
  name?: string; // function or variable name
  source_mapping?: {
    filename_relative?: string;
    lines?: number[]; // Slither may provide multiple lines; we pick the first as representative
  };
};

type EtherscanResponse = {
  status: string;
  message: string;
  result: Array<{
    SourceCode: string;      // Either plain Solidity OR wrapped JSON of sources
    ContractName: string;    // Top-level contract name used to infer main file
    CompilerVersion: string;
  }>;
};

type OllamaResponse = {
  response?: string; // LLM output (full Markdown)
  error?: string;
};

/** Etherscan “multi-file” payload shape after unwrapping {{ ... }} */
type EtherscanMultiSource = {
  sources: Record<string, { content: string }>;
};

/** SWC information attached to each normalized issue (only when mapping is reliable) */
type SWCMeta = {
  id?: string;           // e.g., "SWC-112"
  title: string;         // e.g., "Delegatecall to Untrusted Callee"
  remediation: string;   // Remediation guidance from SWC
  references: string[];  // Outbound reading links (if available)
};

type Impact = "High" | "Medium" | "Low" | "Informational";

// Normalized issue is the shape produced once for both deterministic and LLM paths
type NormalizedIssue = ReturnType<typeof normalizeIssue>;
type Location = { file: string; line: number | null; element: string };

// ────────────────────────── helpers: grouping & locations ──────────────────────────

/**
 * Deduplicate locations that are semantically identical (same file/line/element).
 * Useful when Slither returns repeated pointers for the same thing.
 */
function uniqueLocations(locs: Location[]): Location[] {
  const seen = new Set<string>();
  return locs.filter((l) => {
    const k = `${l.file}:${l.line ?? ""}:${l.element}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * Merge duplicates for checks that naturally repeat per element.
 * Example: "missing-zero-check" may point to the same `yourAddress` parameter across several lines.
 * We group such issues under one item and aggregate their locations.
 */
function groupByCheckAndElement(items: NormalizedIssue[]): NormalizedIssue[] {
  const grouped = new Map<string, NormalizedIssue>();
  const passthrough: NormalizedIssue[] = [];

  for (const it of items) {
    if (it.check === "missing-zero-check") {
      const elem = it.locations.find((l) => l.element)?.element ?? "";
      const key = `${it.check}@@${elem}`;
      const existing = grouped.get(key);
      if (existing) {
        existing.locations = uniqueLocations([...existing.locations, ...it.locations]);
      } else {
        // Clone to avoid mutating the original item
        grouped.set(key, { ...it, locations: uniqueLocations(it.locations.slice()) });
      }
    } else {
      passthrough.push(it);
    }
  }
  return [...passthrough, ...grouped.values()];
}

/**
 * Render a compact, deduped list of locations like:
 *   - src/Contract.sol:12 (element: doThing(bytes4))
 */
function formatLocations(locs: Location[]): string[] {
  const seen = new Set<string>();
  const rows: string[] = [];
  for (const l of locs) {
    const key = `${l.file}:${l.line ?? ""}:${l.element}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const linePart = l.line != null ? `:${l.line}` : "";
    const elemPart = l.element ? ` (element: ${l.element})` : "";
    rows.push(`  - ${l.file}${linePart}${elemPart}`);
  }
  return rows;
}

// ───────────────────────────────────── misc ─────────────────────────────────────

/** Type guard: detect errors that carry a stdout buffer (common for execSync failures) */
function hasStdout(e: unknown): e is { stdout: Buffer | string } {
  return !!e && typeof e === "object" && "stdout" in e;
}

/**
 * Lookup an SWC entry by ID (e.g., "SWC-112") from the local JSON registry package.
 * We stitch the “Id” and raw “markdown” back in alongside the parsed “content”.
 */
export function getSWCEntry(
  id: string
): (import("swc-registry").EntryData & { Id: string; markdown: string }) | undefined {
  const entry = (swcData as Record<string, SWCEntry>)[id];
  if (!entry) return undefined;

  return {
    Id: id,
    markdown: entry.markdown,
    ...entry.content, // Title, Relationships, Description, Remediation
  };
}

/**
 * Extract reference links from the SWC entry, if provided in a structured way.
 * (Note: many entries in this package put references in markdown, not structured JSON.)
 */
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

// ───────────────────────────────── SWC enrichment ─────────────────────────────────

/**
 * Map Slither checks to canonical SWC entries ONLY where accurate.
 * If mapping is not solid (e.g., "missing-zero-check"), we return null to avoid misleading links.
 */
function enrichWithSWC(args: { check: string; description?: string }) {
  const { check, description } = args;
  switch (check) {
    case "controlled-delegatecall":
      return getSWCEntry("SWC-112"); // Delegatecall to untrusted callee
    case "reentrancy-no-eth":
    case "reentrancy-benign":
      return getSWCEntry("SWC-107"); // Reentrancy
    case "low-level-calls":
      return getSWCEntry("SWC-104"); // Unchecked low-level call return value
    // No canonical SWC for "missing-zero-check" → keep null.
    case "missing-zero-check":
      return null;
    default:
      return enrichWithSWCByDescription(description);
  }
}

/**
 * Fuzzy mapping if Slither's "check" doesn’t map directly.
 * Only a couple of very common patterns are recognized to keep it conservative.
 */
function enrichWithSWCByDescription(description?: string) {
  if (!description) return null;
  const lower = description.toLowerCase();
  if (lower.includes("integer overflow") || lower.includes("underflow")) {
    return getSWCEntry("SWC-101");
  }
  if (lower.includes("tx.origin")) return getSWCEntry("SWC-115");
  return null;
}

/**
 * Derive small boolean “facts” from Slither’s free-form description.
 * These facts drive fixed sentences or validations in the renderer.
 */
function deriveFacts(desc: string | undefined) {
  const d = (desc ?? "").toLowerCase();
  return {
    writesAfterCall: d.includes("state variables written after the call"),
    mentionsDelegatecall: d.includes("delegatecall"),
    mentionsLowLevelCall: d.includes(" call(") || d.includes(".call("),
    exactStylePhrase: d.includes("not in mixedcase"),
    mentionsZeroCheck: d.includes("lacks a zero-check") || d.includes("zero-check"),
  };
}

/** Title mapping for presentation (keeps headings consistent and non-hallucinatory) */
function friendlyTitle(check: string): string {
  switch (check) {
    case "controlled-delegatecall":
      return "Controlled Delegatecall";
    case "reentrancy-no-eth":
      return "Reentrancy (no ETH)";
    case "reentrancy-benign":
      return "Reentrancy (benign)";
    case "missing-zero-check":
      return "Missing zero-check (address)";
    case "low-level-calls":
      return "Low-level calls";
    case "naming-convention":
      return "Naming convention";
    default:
      return check;
  }
}

// ───────────────────────── deterministic renderer ─────────────────────────

/**
 * Pure TypeScript Markdown renderer (no LLM):
 * - Groups by impact in a fixed order.
 * - Renders either a single “Function/Element + line” OR a multi-location list.
 * - Adds short, grounded “Issue” and “Recommendation” snippets per check.
 * - Includes SWC title/remediation/references when available.
 */
function renderMarkdownDeterministic(address: string, items: Array<ReturnType<typeof normalizeIssue>>) {
  const byImpact: Record<Impact, ReturnType<typeof normalizeIssue>[]> = {
    High: [],
    Medium: [],
    Low: [],
    Informational: [],
  };
  for (const it of items) {
    (byImpact[it.impact as Impact] ?? (byImpact[it.impact as Impact] = [])).push(it);
  }

  const order: Impact[] = ["High", "Medium", "Low", "Informational"];

  const renderOne = (it: ReturnType<typeof normalizeIssue>) => {
    const locs = (it.locations ?? []) as Location[];
    const main = locs[0];

    // Risk + remediation snippets (check-specific, concise, grounded)
    let risk = "";
    let remediation = "";
    switch (it.check) {
      case "controlled-delegatecall":
        risk = "Uses `delegatecall` to an input-controlled target, executing code in the caller’s context.";
        remediation = "Avoid `delegatecall` to untrusted targets; restrict to immutable/whitelisted addresses or replace with interface calls.";
        break;
      case "reentrancy-no-eth":
        risk = "External call occurs before a state write, enabling reentrancy before effects are applied. A state variable is written after an external call.";
        remediation = "Apply Checks–Effects–Interactions and/or a reentrancy guard; validate/limit the callee.";
        break;
      case "reentrancy-benign":
        risk = "External call followed by a state write (marked benign by Slither for this context). A state variable is written after an external call.";
        remediation = "Prefer CEI or a guard if the function can be externally triggered.";
        break;
      case "missing-zero-check":
        risk = "Target address parameter lacks a `!= address(0)` validation.";
        remediation = "Validate non-zero addresses and check `success` for low-level calls.";
        break;
      case "low-level-calls":
        risk = "Uses low-level calls (`call`/`delegatecall`) that bypass type safety and can fail silently.";
        remediation = "Prefer typed interface calls; if using low-level calls, check `success` and handle returned data.";
        break;
      case "naming-convention":
        risk = "Variable is not in mixedCase.";
        remediation = "Rename variables to mixedCase (e.g., `sVariable`, `sOtherVar`).";
        break;
      default:
        risk = it.description || "See description.";
        remediation = "Follow best practices for this category.";
    }

    // Element/Function labeling + single 'line' when only one location; otherwise show full list
    const elem = locs.find((l) => l.element)?.element || "N/A";
    const isFunctionish =
      /\w+\s*\(.*\)/.test(elem) ||
      ["controlled-delegatecall", "reentrancy-no-eth", "reentrancy-benign", "low-level-calls"].includes(it.check);
    const label = isFunctionish ? "Function" : "Element";
    const line = locs.find((l) => l.line != null)?.line ?? null;

    const headerLines: string[] = [`- Contract: ${main?.file ?? "(unknown file)"}`];
    const locList = formatLocations(locs);
    if (locList.length > 1) {
      headerLines.push(`- Locations:`);
      headerLines.push(...locList);
    } else {
      headerLines.push(`- ${label}: \`${elem}\`${line ? ` (line ${line})` : ""}`);
    }

    // Optional SWC block if mapped reliably
    const swcLines = it.swc
      ? [
          `- **SWC:** ${it.swc.id ? `${it.swc.id}: ` : ""}${it.swc.title}`,
          it.swc.remediation ? `- **SWC Remediation:** ${it.swc.remediation}` : "",
          it.swc.references?.length
            ? "- **References:**\n" + it.swc.references.map((r) => `  - ${r}`).join("\n")
            : "",
        ]
          .filter(Boolean)
          .join("\n")
      : "";

    return [
      `## ${friendlyTitle(it.check)}`,
      ...headerLines,
      `- Confidence: ${it.confidence}`,
      `- Issue: ${risk}`,
      `- Recommendation: ${remediation}`,
      swcLines,
      "",
    ].join("\n");
  };

  const sections = order
    .filter((sev) => (byImpact[sev] ?? []).length)
    .map((sev) => {
      const body = byImpact[sev].map(renderOne).join("\n");
      return `# ${sev} Impact Findings\n\n${body}`;
    })
    .join("\n");

  return sections || `✅ No vulnerabilities found by Slither for ${address}.`;
}

// ───────────────────────── normalize ─────────────────────────

/**
 * Normalize raw Slither items + our derived facts + SWC meta to a single stable shape.
 * Both the deterministic renderer and the LLM path consume this same structure.
 */
function normalizeIssue(issue: {
  check: string;
  impact: string;
  confidence: string;
  description?: string;
  locations: Array<{ file: string; line: number | null; element: string }>;
  facts?: ReturnType<typeof deriveFacts>;
  swc?: null | SWCMeta;
}) {
  return {
    check: issue.check,
    title: friendlyTitle(issue.check),
    impact: issue.impact,
    confidence: issue.confidence,
    description: issue.description ?? "",
    locations: issue.locations ?? [],
    facts: issue.facts ?? deriveFacts(issue.description),
    swc: issue.swc ?? null,
  };
}

// ─────────────────────── validation utilities ───────────────────────

/** Count issues by impact to validate the LLM output matches expected cardinalities */
function countsByImpact(items: Array<{ impact: Impact }>): Record<Impact, number> {
  const init: Record<Impact, number> = { High: 0, Medium: 0, Low: 0, Informational: 0 };
  return items.reduce((acc, it) => {
    acc[it.impact] = (acc[it.impact] ?? 0) + 1;
    return acc;
  }, init);
}

/**
 * Parse rendered Markdown and count headings under each impact section.
 * Supports both "## " and "### " to be a bit tolerant with LLM formatting.
 */
function parseCountsFromMarkdown(md: string): Record<Impact, number> {
  const impacts: Impact[] = ["High", "Medium", "Low", "Informational"];
  const result: Record<Impact, number> = { High: 0, Medium: 0, Low: 0, Informational: 0 };
  for (const sev of impacts) {
    const section = md.split(new RegExp(`^# ${sev} Impact Findings\\s*$`, "m"))[1] || "";
    const count2 = (section.match(/^## /gm) || []).length;
    const count3 = (section.match(/^### /gm) || []).length;
    result[sev] = Math.max(count2, count3);
  }
  return result;
}

/** Hard rule: forbid inline anchors like [text](#anchor) that often come from hallucinated headings */
function containsForbiddenAnchors(md: string) {
  return /\]\(#.+?\)/.test(md);
}

/** Hard rule: ensure CEI guidance sentence appears when Slither says "state variables written after the call" */
function missingWritesAfterCallSentence(md: string, items: NormalizedIssue[]): boolean {
  const needs = items.some((i) => i.facts?.writesAfterCall);
  if (!needs) return false;
  return !md.includes("A state variable is written after an external call.");
}

/**
 * Validate LLM output against:
 * - counts per impact,
 * - no inline anchors,
 * - and the “writes-after-call” sentence when required.
 * If any check fails, caller should fall back to deterministic renderer.
 */
function validateOrFallback(md: string, enrichedIssues: NormalizedIssue[]): boolean {
  const expected = countsByImpact(enrichedIssues.map((i) => ({ impact: i.impact as Impact })));
  const seen = parseCountsFromMarkdown(md);

  const impacts: Impact[] = ["High", "Medium", "Low", "Informational"];
  const countsOk = impacts.every((sev) => expected[sev] === seen[sev]);

  const anchorsOk = !containsForbiddenAnchors(md);
  const writesOk = !missingWritesAfterCallSentence(md, enrichedIssues);

  return countsOk && anchorsOk && writesOk;
}

// ───────────────────────── fetching source ─────────────────────────

/**
 * Fetch verified source code from Sepolia Etherscan.
 * Supports:
 *  - Flattened single file (starts with `pragma`)
 *  - Multi-file JSON payload wrapped as `{{ ... }}` (Etherscan convention)
 * Writes files under TMP and returns the main file path to run Slither against.
 */
async function fetchContractSource(address: string): Promise<string> {
  const url = `https://api-sepolia.etherscan.io/api?module=contract&action=getsourcecode&address=${address}&apikey=${ETHERSCAN_API_KEY}`;
  const res = await fetch(url);
  const data = (await res.json()) as EtherscanResponse;

  if (!data.result || !data.result[0]?.SourceCode) {
    throw new Error("No verified source found for this address.");
  }

  const rawSource = data.result[0].SourceCode;
  const contractName = data.result[0].ContractName;

  fs.mkdirSync(TMP, { recursive: true });

  // Case 1: Flattened single file
  if (rawSource.trim().startsWith("pragma")) {
    const filePath = path.join(TMP, `${contractName}.sol`);
    fs.writeFileSync(filePath, rawSource);
    return filePath;
  }

  // Case 2: Etherscan’s multi-file JSON, wrapped with extra braces: "{{ ... }}"
  if (rawSource.trim().startsWith("{{")) {
    const parsed = JSON.parse(rawSource.slice(1, -1)) as EtherscanMultiSource;

    for (const [fileName, fileData] of Object.entries(parsed.sources)) {
      const outPath = path.join(TMP, fileName);
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, fileData.content, "utf-8");
    }

    // Try to find the main file using the contract name
    const candidate = Object.keys(parsed.sources).find((fileName) =>
      fileName.endsWith(`${contractName}.sol`)
    );
    if (!candidate) {
      throw new Error(`Main contract ${contractName}.sol not found in sources`);
    }
    return path.join(TMP, candidate);
  }

  // If it’s neither a plain Solidity file nor wrapped multi-source JSON:
  throw new Error("Unknown SourceCode format returned by Etherscan");
}

// ───────────────────────── main ─────────────────────────

/**
 * Orchestrates the whole audit:
 *  - Downloads sources,
 *  - Runs Slither,
 *  - Normalizes/enriches findings,
 *  - Renders via deterministic or constrained LLM (with guardrails),
 *  - Writes audit-summary.md and returns the Markdown.
 */
export async function runAudit(address: string) {
  console.log(`📥 Fetching source for ${address}...`);
  const contractPath = await fetchContractSource(address);
  console.log('%%%% contractPath: ' + contractPath);

  // Defensive: if the “main file” was actually a JSON blob, unpack it (covers edge Etherscan returns)
  const raw = fs.readFileSync(contractPath, "utf-8").trim();
  const tryParseEtherscanJson = (txt: string): EtherscanMultiSource | null => {
    if (txt.startsWith("{{") && txt.endsWith("}}")) {
      try {
        return JSON.parse(txt.slice(1, -1)) as EtherscanMultiSource;
      } catch {
        return null;
      }
    }
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
    // Rebuild TMP with the multi-file layout
    fs.rmSync(TMP, { recursive: true, force: true });
    fs.mkdirSync(TMP, { recursive: true });
    for (const [fileName, fileData] of Object.entries(srcJson.sources)) {
      const outPath = path.join(TMP, fileName);
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, fileData.content, "utf-8");
    }
  } else {
    // Nothing to unpack; ensure TMP exists
    fs.mkdirSync(TMP, { recursive: true });
  }

  console.log("🔍 Running Slither...");

  // Execute Slither and capture its JSON output. Slither returns non-zero when it finds findings,
  // so we must read stdout from the thrown error to obtain the JSON.
  let output: string;
  try {
    // Make the target path relative to TMP, since we set cwd: TMP
    const targetArg = path.relative(TMP, contractPath) || ".";
    console.log('--- ' + targetArg);

    // Call slither on that file (or "." if somehow empty). Using execFileSync avoids shell quoting issues.
    output = execFileSync(
      "slither",
      [targetArg, "--filter-paths", "@openzeppelin", "--json", "-"],
      { cwd: TMP }
    ).toString();
  } catch (err: unknown) {
    // Slither returns non-zero when it finds issues; stdout still has valid JSON
    if (hasStdout(err)) {
      const stdout = typeof err.stdout === "string" ? err.stdout : err.stdout.toString();
      output = stdout;
    } else {
      throw err;
    }
  }

  console.log("📝 Parsing Slither report...");
  const report = JSON.parse(output) as SlitherReport;

  console.log("📝 Running AI summarizer...");

  // Normalize Slither detectors to a clean, renderer-friendly shape.
  const issues =
    report?.results?.detectors?.map((d) => ({
      check: d.check,
      impact: d.impact,
      confidence: d.confidence,
      description: d.description,
      locations:
        (d.elements ?? []).map((e) => ({
          file: e.source_mapping?.filename_relative ?? "",
          line: e.source_mapping?.lines?.[0] ?? null,
          element: e.name ?? "",
        })) ?? [],
      facts: deriveFacts(d.description),
    })) ?? [];

  if (issues.length === 0) {
    console.log("✅ No vulnerabilities found");
    return `✅ No vulnerabilities found by Slither for this contract (${address}).`;
  }

  // Attach SWC metadata (only when mapping is reliable) and normalize.
  const enrichedIssuesRaw = issues.map((issue) => {
    const swcEntry = enrichWithSWC({
      check: issue.check,
      description: issue.description,
    });
    return normalizeIssue({
      ...issue,
      swc: swcEntry
        ? {
            id: swcEntry.Id,
            title: swcEntry.Title,
            remediation: swcEntry.Remediation,
            references: getReferences(swcEntry),
          }
        : null,
    });
  });

  // Group duplicates (e.g., multiple lines for same "missing-zero-check" target)
  const enrichedIssues = groupByCheckAndElement(enrichedIssuesRaw);

  // 1) Deterministic (no LLM), if explicitly requested
  if (process.env.AUDIT_RENDERER === "deterministic") {
    const md = renderMarkdownDeterministic(address, enrichedIssues);
    fs.writeFileSync("audit-summary.md", md);
    console.log("✅ Audit complete (deterministic): audit-summary.md");
    return md;
  }

  // 2) Constrained LLM: strict prompt + post-render validation (falls back if drift detected)
  const allowedTitles = [
    "Controlled Delegatecall",
    "Reentrancy (no ETH)",
    "Reentrancy (benign)",
    "Missing zero-check (address)",
    "Low-level calls",
    "Naming convention",
  ];

  const prompt = `
  You are a Solidity security auditor. Follow these rules EXACTLY:

  - Use ONLY the issues provided in JSON. Do NOT invent categories, links, anchors, or findings.
  - Group by the provided \`impact\` value EXACTLY (High, Medium, Low, Informational). Do NOT reclassify any item.
  - Headings MUST come from the per-item "title" field and the allowed set: ${JSON.stringify(allowedTitles)}.
  - If "facts.writesAfterCall" is true, include the exact sentence:
    "A state variable is written after an external call."
  - For "missing-zero-check", describe the risk as missing non-zero **address** validation (not return-value checks).
  - Use the exact file path and function name from "locations".
  - References: include ONLY "swc.references" (if any). Do NOT add other links or inline anchors.
  - Keep items concise.

  Findings for ${address}:
  ${JSON.stringify(enrichedIssues, null, 2)}

  Produce Markdown with sections per impact and items using the given "title".
  `.trim();

  const aiRes = await fetch("http://localhost:11434/api/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "mistral", prompt, stream: false }),
  });

  // LLM path: validate output; if it drifts, use deterministic renderer instead.
  const data = (await aiRes.json()) as OllamaResponse;
  let md = data.response ?? "";
  if (!validateOrFallback(md, enrichedIssues)) {
    md = renderMarkdownDeterministic(address, enrichedIssues);
  }

  fs.writeFileSync("audit-summary.md", md);
  console.log("✅ Audit complete: audit-summary.md");
  return md;
}

import fs from "fs";
import fetch from "node-fetch";

async function summarizeSlither() {
  const raw = fs.readFileSync("slither-report.json", "utf-8");
  const report = JSON.parse(raw);

  const issues = report["results"]["detectors"].map((d: any) => ({
    check: d["check"],
    impact: d["impact"],
    confidence: d["confidence"],
    description: d["description"],
    elements: d["elements"].map((e: any) => e["name"]),
  }));

  const prompt = `
You are a Solidity security auditor.
Here is a Slither static analysis result:
${JSON.stringify(issues, null, 2)}

1. Summarize findings in plain English.
2. Explain risks (High/Medium/Low).
3. Suggest developer fixes.
Format as Markdown.
`;

  const response = await fetch("http://localhost:11434/api/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "mistral",
      prompt: prompt,
      stream: false,
    }),
  });

  type OllamaResponse = {
    response: string;
  };

  const data = (await response.json()) as OllamaResponse;
  console.log(data.response);
}

summarizeSlither();

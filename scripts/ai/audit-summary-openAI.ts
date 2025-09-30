import "dotenv/config";
import fs from "fs";
import OpenAI from "openai";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

async function summarizeSlither() {
  const raw = fs.readFileSync("slither-report.json", "utf-8");
  const report = JSON.parse(raw);

  // Take only the vulnerabilities
  const issues = report["results"]["detectors"].map((d: any) => ({
    check: d["check"],
    impact: d["impact"],
    confidence: d["confidence"],
    description: d["description"],
    elements: d["elements"].map((e: any) => e["name"]),
  }));

  const prompt = `
You are a smart contract security auditor.
Here is a Slither static analysis result:
${JSON.stringify(issues, null, 2)}

1. Summarize the findings in plain English.
2. Explain the risks (High/Medium/Low).
3. Suggest practical fixes for a Solidity developer.
Format as a Markdown report.
`;

  const completion = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: prompt }],
  });

  console.log(completion.choices[0].message.content);
}

summarizeSlither();

"use client";

import * as React from "react";

export default function AuditPage() {
  const [address, setAddress] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [report, setReport] = React.useState("");

  const handleAudit = async () => {
    setLoading(true);
    setReport("");

    try {
      const res = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address }),
      });

      const data = await res.json();

      if (!res.ok) {
        // ✅ show backend error message instead of generic
        setReport(`❌ Error: ${data.error || "Audit failed"}`);
        return;
      }

      setReport(data.report);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setReport(`❌ Error: ${message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center py-10 px-4">
      <div className="max-w-2xl w-full bg-white shadow-lg rounded-2xl p-6">
        <h1 className="text-2xl font-bold mb-4">🤖 Smart Contract Audit Agent</h1>
        <p className="text-gray-700 mb-6">
          This AI agent analyzes verified smart contracts on Etherscan. 
          It runs <b>Slither</b> for static analysis and then uses an 
          <b> AI model</b> to explain the vulnerabilities in plain English.
        </p>

        <div className="flex items-center gap-2 mb-4">
          <input
            type="text"
            placeholder="Enter contract address (0x...)"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            className="flex-1 border rounded-xl px-4 py-2 text-sm focus:ring-2 focus:ring-indigo-500 text-gray-900"
          />
          <button
            onClick={handleAudit}
            disabled={loading || !address}
            className="bg-indigo-600 text-white px-5 py-2 rounded-xl text-sm font-medium disabled:bg-gray-400"
          >
            {loading ? "Auditing..." : "Run Audit"}
          </button>
        </div>

        {report && (
          <div className="mt-6">
            <h2 className="text-lg font-semibold mb-2">📄 Audit Report</h2>
            <pre className="whitespace-pre-wrap bg-gray-100 p-4 rounded-xl text-sm text-gray-800">
              {report}
            </pre>
          </div>
        )}
      </div>
    </div>
  );

}

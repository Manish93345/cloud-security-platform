import { useState } from "react";

function App() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);

  const runScan = async () => {
    setLoading(true);
    const response = await fetch("http://127.0.0.1:5000/scan");
    const result = await response.json();
    setReport(result);
    setLoading(false);
  };

  return (
    <div style={{ padding: "40px", fontFamily: "Arial" }}>
      <h2>Cloud Security Automation Platform 🚀</h2>

      <button onClick={runScan} disabled={loading}>
        {loading ? "Scanning..." : "Start Scan"}
      </button>

      {report && report.summary && (
        <>
          <h3>Summary</h3>
          <ul>
            <li>Total: {report.summary?.total_findings}</li>
            <li>High: {report.summary?.high}</li>
            <li>Medium: {report.summary?.medium}</li>
            <li>Critical: {report.summary?.critical}</li>
          </ul>

          <h3>Findings</h3>
          <pre>{JSON.stringify(report.findings, null, 2)}</pre>
        </>
      )}
    </div>
  );
}

export default App;

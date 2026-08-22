import { useState } from "react";

function App() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const token = localStorage.getItem("access");

  const runScan = async () => {
    setLoading(true);
    const response = await fetch("http://127.0.0.1:8000/api/scan/", {
      headers: {
        "Authorization": `Bearer ${token}`
      }
    });
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
          <table border="1" cellPadding="8" style={{ marginTop: "10px" }}>
            <thead>
              <tr>
                <th>Service</th>
                <th>Resource</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {report.findings.map((item, index) => (
                <tr key={index}>
                  <td>{item.service}</td>
                  <td>{item.resource}</td>
                  <td>{item.port || "-"}</td>
                  <td>{item.protocol || "-"}</td>
                  <td style={{
                    color:
                      item.risk === "CRITICAL"
                        ? "darkred"
                        : item.risk === "HIGH"
                          ? "red"
                          : item.risk === "MEDIUM"
                            ? "orange"
                            : "green"
                  }}>
                    {item.risk}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

        </>
      )}
    </div>
  );
}

export default App;

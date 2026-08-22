import { useEffect, useState } from "react";

function History() {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    const token = localStorage.getItem("access");

    fetch("http://127.0.0.1:8000/api/history/", {
      headers: {
        "Authorization": `Bearer ${token}`
      }
    })
      .then(res => res.json())
      .then(data => setHistory(data));
  }, []);

  return (
    <div>
      <h2>Scan History</h2>
      <ul>
        {history.map((item, index) => (
          <li key={index}>
            {item.timestamp} — High: {item.summary.high}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default History;

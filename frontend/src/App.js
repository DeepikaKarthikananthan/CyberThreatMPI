import React, { useState } from "react";
import axios from "axios";
import { Bar } from "react-chartjs-2";
import "chart.js/auto";

function App() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);

  const handleUpload = async () => {
    const formData = new FormData();
    formData.append("file", file);

    const response = await axios.post(
      "http://127.0.0.1:8000/analyze",
      formData
    );

    setResult(response.data);
  };

  const getRiskLevel = (score) => {
    if (score < 5) return "Low Risk";
    if (score < 15) return "Medium Risk";
    return "High Risk";
  };

  return (
    <div style={{ padding: "40px", fontFamily: "Arial" }}>
      <h1>Distributed Cyber Threat Analyzer</h1>

      <input
        type="file"
        onChange={(e) => setFile(e.target.files[0])}
      />

      <button onClick={handleUpload} style={{ marginLeft: "10px" }}>
        Analyze
      </button>

      {result && (
        <div style={{ marginTop: "30px" }}>
          <h2>Analysis Result</h2>
          <p><strong>Total Logs:</strong> {result.total_logs}</p>
          <p><strong>Threat Score:</strong> {result.global_threat_score}</p>
          <p><strong>Execution Time:</strong> {result.execution_time} sec</p>
          <p><strong>Risk Level:</strong> {getRiskLevel(result.global_threat_score)}</p>

          <Bar
            data={{
              labels: ["Threat Score"],
              datasets: [
                {
                  label: "Threat Score",
                  data: [result.global_threat_score],
                },
              ],
            }}
          />
        </div>
      )}
    </div>
  );
}

export default App;

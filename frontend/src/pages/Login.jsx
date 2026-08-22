import { useState } from "react";

function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleLogin = async () => {
    const response = await fetch("http://127.0.0.1:8000/api/token/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (data.access) {
      localStorage.setItem("access", data.access);
      alert("Login successful 🚀");
    } else {
      alert("Login failed");
    }
  };

  return (
    <div>
      <h2>Login</h2>
      <input
        placeholder="Username"
        onChange={(e) => setUsername(e.target.value)}
      />
      <br /><br />
      <input
        type="password"
        placeholder="Password"
        onChange={(e) => setPassword(e.target.value)}
      />
      <br /><br />
      <button onClick={handleLogin}>Login</button>
    </div>
  );
}

export default Login;

import { Routes, Route } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import History from "./pages/History";
import Layout from "./components/Layout";
import Login from "./pages/Login";

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/history" element={<History />} />
        <Route path="/login" element={<Login />} />
      </Routes>
    </Layout>
  );
}

export default App;

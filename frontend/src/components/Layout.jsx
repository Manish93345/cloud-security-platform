import { Link } from "react-router-dom";

function Layout({ children }) {
  return (
    <div style={{ display: "flex" }}>
      <div style={{ width: "200px", padding: "20px", background: "#f4f4f4" }}>
        <h3>Cloud SaaS</h3>
        <Link to="/">Dashboard</Link>
        <br /><br />
        <Link to="/history">History</Link>
      </div>

      <div style={{ flex: 1, padding: "40px" }}>
        {children}
      </div>
    </div>
  );
}

export default Layout;

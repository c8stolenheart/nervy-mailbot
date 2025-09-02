import { useEffect, useState } from "react";

function App() {
  const [user, setUser] = useState({});
  const [emails, setEmails] = useState([]);

  const userId = window.Telegram?.WebApp?.initDataUnsafe?.user?.id || "demo";

  useEffect(() => {
    fetch(`/api/user/${userId}`)
      .then(res => res.json())
      .then(setUser);

    fetch(`/api/emails/${userId}`)
      .then(res => res.json())
      .then(setEmails);
  }, [userId]);

  return (
    <div style={{ padding: 20, fontFamily: "sans-serif" }}>
      <h2>☁️ iMegatron CloudMail</h2>
      <p><b>User:</b> {userId}</p>
      <p><b>Expiry:</b> {user.expiry || "N/A"}</p>
      <p><b>Limit:</b> {user.limit || 0}</p>
      <p><b>Used:</b> {user.used || 0}</p>
      <h3>📧 Emails</h3>
      <ul>
        {emails.map((e, i) => (
          <li key={i}>{typeof e === "string" ? e : e.address}</li>
        ))}
      </ul>
    </div>
  );
}

export default App;

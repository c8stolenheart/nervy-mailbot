import { useEffect, useState } from "react";

function App() {
  const [user, setUser] = useState({});
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(true);

  const tg = window.Telegram?.WebApp;
  const userId = tg?.initDataUnsafe?.user?.id || "demo";

  useEffect(() => {
    tg?.ready();
    tg?.expand();

    Promise.all([
      fetch(`/api/user/${userId}`).then(res => res.json()),
      fetch(`/api/emails/${userId}`).then(res => res.json())
    ])
      .then(([userData, emailData]) => {
        setUser(userData);
        setEmails(emailData);
      })
      .finally(() => setLoading(false));
  }, [userId, tg]);

  if (loading) return <p style={{ padding: 20 }}>⏳ Loading...</p>;

  return (
    <div style={{ padding: 20, fontFamily: "sans-serif" }}>
      <h2>☁️ iMegatron CloudMail</h2>
      <p><b>User:</b> {userId}</p>
      <p><b>Expiry:</b> {user.expiry || "N/A"}</p>
      <p><b>Limit:</b> {user.limit || 0}</p>
      <p><b>Used:</b> {user.used || 0}</p>
      <h3>📧 Emails</h3>
      <ul>
        {emails.length > 0 ? (
          emails.map((e, i) => (
            <li key={i}>{typeof e === "string" ? e : e.address}</li>
          ))
        ) : (
          <li>No emails yet</li>
        )}
      </ul>
    </div>
  );
}

export default App;

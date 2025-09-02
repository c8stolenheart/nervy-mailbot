<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  
</head>
<body>

  <h1>I-Megatron Bot ⚡</h1>
  <p>
    Telegram bot for <b>cPanel email management</b> with advanced features like:
  </p>
  <ul>
    <li>📧 Create & delete mailboxes</li>
    <li>🔑 Per-user default passwords (randomized)</li>
    <li>⏳ Subscription system (expiry, usage limits, suspend/ban)</li>
    <li>📩 IMAP polling for new mail alerts</li>
    <li>🎟 Invite & redeem codes system</li>
    <li>📊 Stats, reports, quotas, and broadcast tools</li>
    <li>🔄 Auto-update from GitHub</li>
  </ul>

  <hr>

  <h2>🚀 Features</h2>
  <h3>User Features</h3>
  <ul>
    <li>Create / delete email accounts</li>
    <li>Reset and show default password</li>
    <li>View last inbox messages</li>
    <li>Bulk create multiple accounts</li>
    <li>Redeem invite codes</li>
  </ul>

  <h3>Admin Features</h3>
  <ul>
    <li>Add / reset subscriptions</li>
    <li>Ban / suspend users</li>
    <li>Send broadcasts</li>
    <li>Set quotas</li>
    <li>View detailed reports</li>
    <li>Update bot from GitHub</li>
    <li>Check bot uptime & status</li>
  </ul>

  <hr>

  <h2>📂 Project Structure</h2>
  <pre>
imegatron-bot/
│── bot.py              # Main bot script
│── config.json       # Config (tokens, cPanel details, etc.)
│── subs.json         # Subscriptions database (auto-generated)
│── logs.txt          # Logs (auto-generated)
│── requirements.txt  # Python dependencies
│── README.md         # Documentation
  </pre>

  <hr>

  <h2>⚙️ Setup Instructions</h2>

  <h3>1. Clone the repo</h3>
  <pre><code>git clone https://github.com/&lt;your-username&gt;/imegatron-bot.git
cd imegatron-bot</code></pre>

  <h3>2. Create and edit config.json</h3>
  <pre><code>{
  "BOT_TOKEN": "YOUR_TELEGRAM_BOT_TOKEN",
  "ADMIN_ID": 123456789,
  "CPANEL_USER": "your_cpanel_user",
  "CPANEL_PASS": "your_cpanel_api_token_or_pass",
  "CPANEL_HOST": "https://your-cpanel-host:2083",
  "DOMAIN": "example.com",
  "DB_FILE": "subs.json",
  "LOG_FILE": "logs.txt",
  "DEFAULT_PASSWORD": "ChangeMe123",
  "MAIL_CHECK_INTERVAL": 10
}</code></pre>

  <h3>3. Install dependencies</h3>
  <pre><code>pip install -r requirements.txt</code></pre>

  <h3>4. Run the bot</h3>
  <pre><code>python p.py</code></pre>

  <hr>

  <h2>🛡️ Notes</h2>
  <ul>
    <li><code>subs.json</code> and <code>logs.txt</code> are ignored by Git (<code>.gitignore</code>) so your local data is <b>safe</b>.</li>
    <li>If running on a server, create a <code>systemd</code> service to keep the bot always running.</li>
    <li>Tested with <b>Python 3.10+</b>.</li>
  </ul>

  <hr>

  <h2>📜 License</h2>
  <p>MIT License – feel free to modify and use.</p>

</body>
</html>

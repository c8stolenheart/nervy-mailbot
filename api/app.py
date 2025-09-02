from flask import Flask, jsonify
import json, os

DB_FILE = os.path.join(os.path.dirname(__file__), "subs.json")

app = Flask(__name__)

def load_db():
    if os.path.exists(DB_FILE):
        return json.load(open(DB_FILE))
    return {}

@app.route("/api/user/<user_id>")
def user_info(user_id):
    db = load_db()
    return jsonify(db.get(user_id, {}))

@app.route("/api/emails/<user_id>")
def user_emails(user_id):
    db = load_db()
    return jsonify(db.get(user_id, {}).get("emails", []))

@app.route("/api/stats")
def stats():
    db = load_db()
    total_users = sum(1 for u in db.values() if isinstance(u, dict))
    total_emails = sum(u.get("used", 0) for u in db.values() if isinstance(u, dict))
    return jsonify({"users": total_users, "emails": total_emails})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

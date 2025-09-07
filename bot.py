"""
I-Megatron Bot (Polling Version)
================
Telegram bot for cPanel email management with:
- Subscriptions, expiry, limits, ban/suspend
- Mailbox creation/deletion
- Per-user default passwords
- IMAP polling for new-mail (every X seconds)
- Invite/redeem system with days + limit
- Logging
- Typed commands + button menus
"""

import os, json, requests, asyncio, imaplib, email, logging, random, string
import subprocess
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from telegram import (
    Update, ReplyKeyboardMarkup,
    InlineKeyboardMarkup, InlineKeyboardButton
)
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, ContextTypes, filters
)
START_TIME = datetime.now()

# ---------------- CONFIG ----------------
with open("config.json") as f:
    CONFIG = json.load(f)

BOT_TOKEN = CONFIG["BOT_TOKEN"]
# Ensure ADMIN_ID is always a list (even if only one is provided)
ADMIN_ID = CONFIG["ADMIN_ID"]
if isinstance(ADMIN_ID, int):   # convert single admin ID to list
    ADMIN_ID = [ADMIN_ID]
CPANEL_USER = CONFIG["CPANEL_USER"]
CPANEL_PASS = CONFIG["CPANEL_PASS"]
CPANEL_HOST = CONFIG["CPANEL_HOST"]
DOMAIN = CONFIG["DOMAIN"]
DB_FILE = CONFIG["DB_FILE"]
LOG_FILE = CONFIG["LOG_FILE"]
DEFAULT_PASSWORD = CONFIG.get("DEFAULT_PASSWORD", "ChangeMe123")
MAIL_CHECK_INTERVAL = CONFIG.get("MAIL_CHECK_INTERVAL", 10)

logging.basicConfig(level=logging.INFO)

# ---------------- HELPERS ----------------
def load_db():
    if os.path.exists(DB_FILE):
        try: return json.load(open(DB_FILE))
        except: return {}
    return {}

def save_db(db):
    json.dump(db, open(DB_FILE, "w"), indent=2)

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(length))

def log_action(user_id, action):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {user_id}: {action}\n")

def check_sub(user_id):
    # Admin bypass
if str(user_id) in map(str, ADMIN_ID):
    return True, {"admin": True}


    db = load_db()
    user = db.get(str(user_id))
    if not user:
        return False, "❌ No subscription."
    if datetime.fromisoformat(user["expiry"]) < datetime.now():
        return False, "⛔ Subscription expired."
    if user.get("suspended", False):
        return False, "🚫 Suspended."
    if user["used"] >= user["limit"]:
        return False, "⚠️ Limit reached."
    return True, user


def cpanel_headers(): 
    return {"Authorization": f"cpanel {CPANEL_USER}:{CPANEL_PASS}"}

def get_user_password(user_id): 
    db = load_db()
    uid = str(user_id)

    # If user already has a password → return it
    if uid in db and "default_password" in db[uid]:
        return db[uid]["default_password"]

    # If not → generate one, save it, return it
    new_pw = generate_password()
    if uid not in db:
        db[uid] = {
            "expiry": "1970-01-01T00:00:00",
            "limit": 0,
            "used": 0,
            "emails": [],
            "default_password": new_pw
        }
    else:
        db[uid]["default_password"] = new_pw

    save_db(db)
    return new_pw

def set_user_password(user_id, pw):
    db = load_db()
    if str(user_id) in db:
        db[str(user_id)]["default_password"] = pw
        save_db(db)

def generate_invite(): 
    return ''.join(random.choices(string.ascii_uppercase+string.digits, k=8))

def extract_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain" and not part.get("Content-Disposition"):
                return part.get_payload(decode=True).decode(errors="ignore")
            elif ctype == "text/html" and not part.get("Content-Disposition"):
                html = part.get_payload(decode=True).decode(errors="ignore")
                return BeautifulSoup(html, "html.parser").get_text()
    else:
        ctype = msg.get_content_type()
        if ctype == "text/plain":
            return msg.get_payload(decode=True).decode(errors="ignore")
        elif ctype == "text/html":
            html = msg.get_payload(decode=True).decode(errors="ignore")
            return BeautifulSoup(html, "html.parser").get_text()
    return "(no text body)"

async def safe_reply(update, text=None, document=None):
    try:
        if update.message:
            if text: return await update.message.reply_text(text)
            if document: return await update.message.reply_document(document)
        elif update.callback_query:
            if text: return await update.callback_query.message.reply_text(text)
            if document: return await update.callback_query.message.reply_document(document)
    except Exception as e:
        logging.error(f"safe_reply error: {e}")

# ---------------- MENUS ----------------
def user_menu():
    return ReplyKeyboardMarkup(
        [
            ["📊 My Info","📧 My Emails"],
            ["➕ Create","🗑 Delete"],
            ["🔑 Password","📩 Inbox"],
            ["🔑 Default PW","👁 Show PW","♻ Reset PW"],
            ["🎟 Redeem Code","ℹ️ Help"]
        ], resize_keyboard=True
    )

def admin_menu():
    return ReplyKeyboardMarkup(
        [
            ["👤 AddSub","♻ Reset Usage"],
            ["🚫 Ban","⏸ Suspend"],
            ["📊 Stats","📑 Report"],
            ["📢 Broadcast","🎟 Invite"],
            ["💾 Quota","🔄 Update Bot"],
            ["📡 Bot Status","⬅ Back"]
        ], resize_keyboard=True
    )
# ---------------- USER COMMANDS ----------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id); db = load_db()
    if uid not in db:
        db[uid] = {
            "expiry":"1970-01-01T00:00:00",
            "limit":0,"used":0,
            "emails":[],
            "default_password": generate_password()
        }
        save_db(db)

    menu = admin_menu() if update.effective_user.id in ADMIN_ID else user_menu()

    await safe_reply(update, "🤖 Welcome to Nervy Mailbot ⚡",)
    if update.message:
        await update.message.reply_text("Choose an option:", reply_markup=menu)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = "📌 Commands:\n"
    text += "🔹 /myinfo, /list, /create <u>, /delete <u>, /password <u> <pw>\n"
    text += "🔹 /inbox <u>, /defaultpassword <pw>, /showdefaultpassword, /resetdefaultpassword\n"
    text += "🔹 /redeem <code>, /bulkcreate <n>\n"
    if update.effective_user.id in ADMIN_ID:
    text += "\n👑 Admin: /addsub, /reset, /ban, /suspend, /stats, /report, /broadcast, /quota, /invite"

    await safe_reply(update, text)

async def myinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid=str(update.effective_user.id); db=load_db()
    if uid not in db: return await safe_reply(update,"❌ No subscription.")
    u=db[uid]
    await safe_reply(update,
        f"📅 Expiry: {u['expiry']}\n📊 Used: {u['used']}/{u['limit']}\n"
        f"📧 Emails: {', '.join([m if isinstance(m,str) else m['address'] for m in u.get('emails',[])]) or 'None'}\n"
        f"🔑 PW: {u.get('default_password')}"
    )
async def bot_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
   if update.effective_user.id not in ADMIN_ID:
    return await safe_reply(update, "⛔ Not authorized.")


    uptime = datetime.now() - START_TIME
    days, seconds = uptime.days, uptime.seconds
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60

    uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"

    text = (
        "✅ Bot is running.\n"
        f"🕒 Uptime: {uptime_str}\n"
        f"📂 DB File: {DB_FILE}\n"
        f"📝 Log File: {LOG_FILE}"
    )

    await safe_reply(update, text)

# ---------------- MAILBOX COMMANDS ----------------
async def create_email(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 1:
        return await safe_reply(update, "Usage: /create username")

    uid = str(update.effective_user.id)
    ok, status = check_sub(uid)
    if not ok:
        return await safe_reply(update, status)

    username = context.args[0]
    pw = get_user_password(uid)
    db = load_db()
    quota = db[uid].get("quota", 1024)

    # Reply fast so Telegram doesn’t timeout
    await safe_reply(update, f"⏳ Creating `{username}@{DOMAIN}` ... please wait.")

    url = f"{CPANEL_HOST}/execute/Email/add_pop"
    data = {"domain": DOMAIN, "email": username, "password": pw, "quota": quota}

    try:
        r = requests.post(url, headers=cpanel_headers(), data=data, verify=False, timeout=60).json()
        if r.get("status") == 1:
            db[uid]["used"] += 1
            db[uid].setdefault("emails", []).append({"address": f"{username}@{DOMAIN}", "password": pw})
            save_db(db)
            log_action(uid, f"Created {username}@{DOMAIN}")
            await safe_reply(update, f"✅ Created {username}@{DOMAIN}\n🔑 {pw}")
        else:
            await safe_reply(update, "⚠️ Mail already taken or error.")
    except Exception as e:
        await safe_reply(update, f"❌ Exception: {e}")


async def list_emails(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid=str(update.effective_user.id); ok,status=check_sub(uid)
    if not ok: return await safe_reply(update,status)
    db=load_db(); emails=db.get(uid,{}).get("emails",[])
    if not emails: return await safe_reply(update,"No emails created.")
    for m in emails:
        email_addr=m["address"] if isinstance(m,dict) else m
        keyboard=InlineKeyboardMarkup([[
            InlineKeyboardButton("📩 Inbox",callback_data=f"inbox:{email_addr}"),
            InlineKeyboardButton("🔑 Reset PW",callback_data=f"reset:{email_addr}"),
            InlineKeyboardButton("🗑 Delete",callback_data=f"delete:{email_addr}")
        ]])
        await safe_reply(update,f"📧 {email_addr}")
        if update.message:
            await update.message.reply_text("Choose action:",reply_markup=keyboard)

async def delete_email(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args)<1: return await safe_reply(update,"Usage: /delete username")
    uid=str(update.effective_user.id); ok,status=check_sub(uid)
    if not ok: return await safe_reply(update,status)

    username=context.args[0]; email_addr=f"{username}@{DOMAIN}"; db=load_db()
    owned=[m["address"] if isinstance(m,dict) else m for m in db.get(uid,{}).get("emails",[])]
    if email_addr not in owned: return await safe_reply(update,"⛔ You don't own this email.")
    url=f"{CPANEL_HOST}/execute/Email/delete_pop"; data={"domain":DOMAIN,"email":username}
    try:
        r=requests.post(url,headers=cpanel_headers(),data=data,verify=False).json()
        if r.get("status")==1:
            db[uid]["emails"]=[m for m in db[uid]["emails"] if (m["address"] if isinstance(m,dict) else m)!=email_addr]
            save_db(db); log_action(uid,f"Deleted {email_addr}")
            await safe_reply(update,f"🗑 Deleted {email_addr}")
        else: await safe_reply(update,"❌ Error deleting email.")
    except Exception as e: await safe_reply(update,f"❌ Exception: {e}")

async def reset_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args)<2: return await safe_reply(update,"Usage: /password username newpass")
    username,newpass=context.args; url=f"{CPANEL_HOST}/execute/Email/passwd_pop"
    data={"domain":DOMAIN,"email":username,"password":newpass}
    try:
        r=requests.post(url,headers=cpanel_headers(),data=data,verify=False).json()
        if r.get("status")==1:
            log_action(update.effective_user.id,f"Changed pw for {username}@{DOMAIN}")
            await safe_reply(update,f"🔑 Password changed for {username}@{DOMAIN}")
        else: await safe_reply(update,"❌ Error resetting password.")
    except Exception as e: await safe_reply(update,f"❌ Exception: {e}")

async def set_defaultpw(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args)<1: return await safe_reply(update,"Usage: /defaultpassword newpass")
    uid=str(update.effective_user.id); set_user_password(uid,context.args[0])
    await safe_reply(update,"✅ Default password updated.")

async def show_defaultpw(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid=str(update.effective_user.id); await safe_reply(update,f"🔑 Default password: {get_user_password(uid)}")

async def reset_defaultpw(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    new_pw = generate_password()
    set_user_password(uid, new_pw)
    await safe_reply(update, f"✅ Default password reset.\n🔑 New Default: {new_pw}")

async def inbox(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args)<1: return await safe_reply(update,"Usage: /inbox username")
    username=context.args[0]; email_addr=f"{username}@{DOMAIN}"; pw=get_user_password(update.effective_user.id)
    try:
        mail=imaplib.IMAP4_SSL(IMAP_HOST,993); mail.login(email_addr,pw); mail.select("inbox")
        _,data_ids=mail.search(None,"ALL"); ids=data_ids[0].split()[-5:]
        if not ids: return await safe_reply(update,"📭 No mails found.")
        for num in ids:
            _,msg_data=mail.fetch(num,"(RFC822)"); msg=email.message_from_bytes(msg_data[0][1])
            body=extract_body(msg); preview=f"📩 Mail in {email_addr}\nFrom: {msg['from']}\nSubject: {msg['subject']}\n---\n{body[:3000]}"
            await safe_reply(update,preview)
        mail.logout()
    except Exception as e: await safe_reply(update,f"❌ Inbox error: {e}")
# ---------------- INLINE HANDLER ----------------
async def inline_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer(); data = query.data
    if data.startswith("inbox:"):
        username = data.split(":",1)[1].split("@")[0]; context.args=[username]
        return await inbox(update, context)
    if data.startswith("reset:"):
        username = data.split(":",1)[1].split("@")[0]
        return await query.edit_message_text(f"Use: /password {username} <newpass>")
    if data.startswith("delete:"):
        username = data.split(":",1)[1].split("@")[0]; context.args=[username]
        return await delete_email(update, context)

# ---------------- ADMIN COMMANDS ----------------
async def add_sub(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id in ADMIN_ID: return await safe_reply(update,"⛔ Not authorized.")
    if len(context.args)<3: return await safe_reply(update,"Usage: /addsub user_id days limit")
    user_id,days,limit=context.args[0],int(context.args[1]),int(context.args[2])
    expiry=datetime.now()+timedelta(days=days); db=load_db()
    db[user_id]={"expiry":expiry.isoformat(),"limit":limit,"used":0,"emails":[],"default_password": generate_password()}
    save_db(db); log_action(ADMIN_ID,f"Added sub for {user_id}")
    await safe_reply(update,f"✅ Subscribed {user_id}\n📅 {expiry.date()} | 📊 Limit {limit}")

async def update_bot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return await safe_reply(update, "⛔ Not authorized.")

    await safe_reply(update, "🔄 Updating bot from GitHub...")

    try:
        # Fetch latest commits
        result1 = subprocess.run(
            ["git", "fetch", "--all"], capture_output=True, text=True
        )
        result2 = subprocess.run(
            ["git", "reset", "--hard", "origin/main"], capture_output=True, text=True
        )

        if result1.returncode == 0 and result2.returncode == 0:
            # Get the latest commit hash
            commit = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True
            ).stdout.strip()

            await safe_reply(update, f"✅ Update complete!\n📌 Commit: `{commit}`\n♻ Restarting bot...")

            # Restart via systemd
            subprocess.Popen(["systemctl", "restart", "imegatron.service"])

        else:
            await safe_reply(update, f"⚠️ Git error:\n{result1.stderr}\n{result2.stderr}")

    except Exception as e:
        await safe_reply(update, f"❌ Update error: {e}")

async def reset_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id!=ADMIN_ID: return await safe_reply(update,"⛔ Not authorized.")
    if len(context.args)<1: return await safe_reply(update,"Usage: /reset user_id")
    user_id=context.args[0]; db=load_db()
    if user_id in db:
        db[user_id]["used"]=0; save_db(db); log_action(ADMIN_ID,f"Reset {user_id}")
        await safe_reply(update,"✅ Reset successfully.")
    else: await safe_reply(update,"❌ User not found.")

async def ban_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id!=ADMIN_ID: return await safe_reply(update,"⛔ Not authorized.")
    if len(context.args)<1: return await safe_reply(update,"Usage: /ban user_id")
    user_id=context.args[0]; db=load_db()
    db[user_id]={"expiry":"1970-01-01T00:00:00","limit":0,"used":0,"emails":[]}
    save_db(db); log_action(ADMIN_ID,f"Banned {user_id}")
    await safe_reply(update,"🚫 User banned.")

async def suspend_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id!=ADMIN_ID: return await safe_reply(update,"⛔ Not authorized.")
    if len(context.args)<1: return await safe_reply(update,"Usage: /suspend user_id")
    user_id=context.args[0]; db=load_db()
    if user_id in db:
        db[user_id]["suspended"]=True; save_db(db); log_action(ADMIN_ID,f"Suspended {user_id}")
        await safe_reply(update,"⏸ User suspended.")
    else: await safe_reply(update,"❌ User not found.")

async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    db = load_db()

    total_users = sum(1 for uid, u in db.items() if isinstance(u, dict) and uid != str(ADMIN_ID))
    total_user_emails = sum(u.get("used", 0) for uid, u in db.items() if isinstance(u, dict) and uid != str(ADMIN_ID))

    admin_emails = db.get(str(ADMIN_ID), {}).get("used", 0)

    text = (
        f"📊 Bot Statistics\n"
        f"👤 Users: {total_users}\n"
        f"📧 User Emails Created: {total_user_emails}\n"
        f"👑 Admin Emails Created: {admin_emails}\n"
        f"📦 Total Emails: {total_user_emails + admin_emails}"
    )

    await safe_reply(update, text)



async def report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return await safe_reply(update, "⛔ Not authorized.")

    db = load_db()
    lines = []

    for uid, info in db.items():
        # skip non-user entries like "invites"
        if not isinstance(info, dict) or "expiry" not in info:
            continue

        expiry = info.get("expiry", "N/A")
        used = info.get("used", 0)
        limit = info.get("limit", 0)
        emails = [
            m["address"] if isinstance(m, dict) else m
            for m in info.get("emails", [])
        ]
        emails_str = ", ".join(emails) if emails else "None"
        suspended = info.get("suspended", False)

        lines.append(
            f"👤 {uid}\n"
            f"📅 Expiry: {expiry}\n"
            f"📊 Used: {used}/{limit}\n"
            f"📧 Emails: {emails_str}\n"
            f"⏸ Suspended: {suspended}"
        )

    if lines:
        await safe_reply(update, "\n\n".join(lines))
    else:
        await safe_reply(update, "No users found.")


async def broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id!=ADMIN_ID: return await safe_reply(update,"⛔ Not authorized.")
    if len(context.args)<1: return await safe_reply(update,"Usage: /broadcast msg")
    msg=" ".join(context.args); db=load_db()
    for uid in db.keys():
        if not uid.isdigit(): continue
        try: await context.bot.send_message(chat_id=int(uid),text=f"📢 {msg}")
        except: pass
    await safe_reply(update,"✅ Broadcast sent.")

async def quota(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id!=ADMIN_ID: return await safe_reply(update,"⛔ Not authorized.")
    if len(context.args)<2: return await safe_reply(update,"Usage: /quota username MB")
    username,mb=context.args[0],int(context.args[1])
    url=f"{CPANEL_HOST}/execute/Email/edit_pop_quota"
    r=requests.post(url,headers=cpanel_headers(),data={"domain":DOMAIN,"email":username,"quota":mb},verify=False).json()
    await safe_reply(update,f"✅ Quota set → {mb}MB" if r.get("status")==1 else "❌ Error.")

async def bulk_create(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /bulkcreate <count>
    Create multiple random email accounts at once.
    """
    if len(context.args) < 1:
        return await safe_reply(update, "Usage: /bulkcreate <count>")

    uid = str(update.effective_user.id)
    ok, status = check_sub(uid)
    if not ok:
        return await safe_reply(update, status)

    try:
        count = int(context.args[0])
    except:
        return await safe_reply(update, "❌ Count must be a number.")

    db = load_db()
    limit_left = db[uid]["limit"] - db[uid]["used"]
    if count > limit_left:
        return await safe_reply(update, f"⚠️ You can only create {limit_left} more emails.")

    pw = get_user_password(uid)
    quota = db[uid].get("quota", 1024)
    created = []

    for _ in range(count):
        username = ''.join(random.choices(string.ascii_lowercase, k=6)) + str(random.randint(1000, 9999))
        url = f"{CPANEL_HOST}/execute/Email/add_pop"
        data = {"domain": DOMAIN, "email": username, "password": pw, "quota": quota}

        try:
            r = requests.post(url, headers=cpanel_headers(), data=data, verify=False, timeout=30).json()
            if r.get("status") == 1:
                db[uid]["used"] += 1
                db[uid].setdefault("emails", []).append({"address": f"{username}@{DOMAIN}", "password": pw})
                created.append(f"{username}@{DOMAIN}")
            else:
                logging.warning(f"Bulkcreate error: {r.get('errors')}")
        except Exception as e:
            logging.error(f"Bulkcreate exception: {e}")

        await asyncio.sleep(1)  # throttle cPanel requests

    save_db(db)
    log_action(uid, f"Bulk created {len(created)} emails")

    if created:
        await safe_reply(update, "✅ Bulk created:\n" + "\n".join(created))
    else:
        await safe_reply(update, "❌ No emails created.")

# ---------------- INVITE / REDEEM ----------------
async def invite(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_ID:
        return await safe_reply(update, "⛔ Not authorized.")

    if len(context.args) < 2:
        return await safe_reply(update, "Usage: /invite days limit")

    days = int(context.args[0])
    limit = int(context.args[1])
    code = generate_invite()

    db = load_db()
    db.setdefault("invites", {})

    if days == 0 and limit == 0:
        # Unlimited invite
        db["invites"][code] = {"unlimited": True}
        msg = f"🎟 Invite code: {code}\n♾ Unlimited (no expiry, no limit)"
    else:
        db["invites"][code] = {"days": days, "limit": limit}
        msg = f"🎟 Invite code: {code}\n📅 {days} days | 📊 {limit} emails"

    save_db(db)
    await safe_reply(update, msg)


async def redeem(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 1:
        return await safe_reply(update, "Usage: /redeem CODE")

    code = context.args[0].strip()
    uid = str(update.effective_user.id)
    db = load_db()

    if code in db.get("invites", {}):
        details = db["invites"].pop(code)

        if details.get("unlimited"):  # Unlimited invite case
            expiry = "2099-12-31T23:59:59"
            limit = float("inf")  # treated as unlimited
            msg = "✅ Subscription active!\n♾ Unlimited (no expiry, no limit)"
        else:
            expiry = (datetime.now() + timedelta(days=details["days"])).isoformat()
            limit = details["limit"]
            msg = f"✅ Subscription active!\n📅 Until {expiry.split('T')[0]} | 📊 Limit {limit}"

        db[uid] = {
            "expiry": expiry,
            "limit": limit,
            "used": 0,
            "emails": [],
            "default_password": generate_password()
        }

        save_db(db)
        log_action(uid, f"Redeemed {code}")
        await safe_reply(update, msg)

    else:
        await safe_reply(update, "❌ Invalid or expired code.")


# ---------------- MAIL CHECKER ----------------
IMAP_HOST = "mail." + DOMAIN

async def check_new_mails(app):
    while True:
        db = load_db()
        for uid, data in db.items():
            if not isinstance(data, dict):
                continue
            for m in data.get("emails", []):
                mailbox = m["address"] if isinstance(m, dict) else m
                pw = m["password"] if isinstance(m, dict) else get_user_password(uid)
                try:
                    mail = imaplib.IMAP4_SSL(IMAP_HOST, 993)
                    mail.login(mailbox, pw)
                    mail.select("inbox")
                    _, ids = mail.search(None, "UNSEEN")
                    ids = ids[0].split()
                    for num in ids:
                        _, msg_data = mail.fetch(num, "(RFC822)")
                        msg = email.message_from_bytes(msg_data[0][1])
                        body = extract_body(msg)
                        preview = (
                            f"📩 New mail in {mailbox}\n"
                            f"From: {msg['from']}\n"
                            f"Subject: {msg['subject']}\n"
                            f"---\n{body[:200]}"
                        )
                        await app.bot.send_message(chat_id=int(uid), text=preview)
                    mail.logout()
                except Exception as e:
                    logging.warning(f"Mail check fail {mailbox}: {e}")

        # ⬇ now uses config.json value
        await asyncio.sleep(MAIL_CHECK_INTERVAL)

# ---------------- BUTTON HANDLER ----------------
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text=update.message.text
    if text=="📊 My Info": return await myinfo(update, context)
    if text=="📧 My Emails": return await list_emails(update, context)
    if text=="➕ Create": return await safe_reply(update,"Usage: /create <username>")
    if text=="🗑 Delete": return await safe_reply(update,"Usage: /delete <username>")
    if text=="🔑 Password": return await safe_reply(update,"Usage: /password <username> <newpass>")
    if text=="📩 Inbox": return await safe_reply(update,"Usage: /inbox <username>")
    if text=="🔑 Default PW": return await safe_reply(update,"Usage: /defaultpassword <pw>")
    if text=="👁 Show PW": return await show_defaultpw(update, context)
    if text=="♻ Reset PW": return await reset_defaultpw(update, context)
    if text=="🎟 Redeem Code": return await safe_reply(update,"Usage: /redeem <code>")
    if text=="📦 Bulk Create": return await safe_reply(update,"Usage: /bulkcreate <count>")
    if text=="ℹ️ Help": return await help_cmd(update, context)

    if update.effective_user.id==ADMIN_ID:
        if text=="👤 AddSub": return await safe_reply(update,"Usage: /addsub <user_id> <days> <limit>")
        if text=="♻ Reset Usage": return await safe_reply(update,"Usage: /reset <user_id>")
        if text=="🚫 Ban": return await safe_reply(update,"Usage: /ban <user_id>")
        if text=="⏸ Suspend": return await safe_reply(update,"Usage: /suspend <user_id>")
        if text=="📊 Stats": return await stats(update, context)
        if text=="📑 Report": return await report(update, context)
        if text=="📢 Broadcast": return await safe_reply(update,"Usage: /broadcast <msg>")
        if text=="🎟 Invite": return await safe_reply(update,"Usage: /invite <days> <limit>")
        if text=="💾 Quota": return await safe_reply(update,"Usage: /quota <username> <mb>")
        if text == "🔄 Update Bot": return await update_bot(update, context)
        if text == "📡 Bot Status": return await bot_status(update, context)
        if text=="⬅ Back": return await start(update, context)

# ---------------- MAIN ----------------
async def on_startup(app): asyncio.create_task(check_new_mails(app))

def main():
    app=Application.builder().token(BOT_TOKEN).post_init(on_startup).build()
    # user
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("myinfo", myinfo))
    app.add_handler(CommandHandler("create", create_email))
    app.add_handler(CommandHandler("list", list_emails))
    app.add_handler(CommandHandler("delete", delete_email))
    app.add_handler(CommandHandler("password", reset_password))
    app.add_handler(CommandHandler("defaultpassword", set_defaultpw))
    app.add_handler(CommandHandler("showdefaultpassword", show_defaultpw))
    app.add_handler(CommandHandler("resetdefaultpassword", reset_defaultpw))
    app.add_handler(CommandHandler("inbox", inbox))
    app.add_handler(CommandHandler("bulkcreate", bulk_create))
    app.add_handler(CommandHandler("redeem", redeem))
    # admin
    app.add_handler(CommandHandler("addsub", add_sub))
    app.add_handler(CommandHandler("reset", reset_user))
    app.add_handler(CommandHandler("ban", ban_user))
    app.add_handler(CommandHandler("suspend", suspend_user))
    app.add_handler(CommandHandler("stats", stats))
    app.add_handler(CommandHandler("report", report))
    app.add_handler(CommandHandler("broadcast", broadcast))
    app.add_handler(CommandHandler("quota", quota))
    app.add_handler(CommandHandler("invite", invite))
    app.add_handler(CommandHandler("status", bot_status))
    app.add_handler(CommandHandler("updatebot", update_bot))
    # buttons
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, button_handler))
    app.add_handler(CallbackQueryHandler(inline_handler))
    logging.info("🚀 I-Megatron started...")
    app.run_polling()

if __name__=="__main__": main()






import streamlit as st
import sqlite3
import bcrypt

# ---------------- DATABASE ----------------
conn = sqlite3.connect("database.db", check_same_thread=False)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password BLOB,
    score INTEGER DEFAULT 0
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS answers (
    username TEXT,
    question TEXT
)
""")
conn.commit()

# ---------------- QUESTIONS ----------------
questions = {
    "Python is a ?": ["Language", "Snake", "Car", "Game", "Language"],
    "Django is a ?": ["Framework", "Database", "IDE", "OS", "Framework"],
    "Which is mutable?": ["Tuple", "List", "String", "Int", "List"]
}

# ---------------- FUNCTIONS ----------------
def register_user(username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cur.execute("INSERT INTO users VALUES (?, ?, 0)", (username, hashed))
    conn.commit()

def login_user(username, password):
    cur.execute("SELECT password FROM users WHERE username=?", (username,))
    data = cur.fetchone()
    if data:
        return bcrypt.checkpw(password.encode(), data[0])
    return False

def answered(username, question):
    cur.execute("SELECT * FROM answers WHERE username=? AND question=?", (username, question))
    return cur.fetchone() is not None

def save_answer(username, question):
    cur.execute("INSERT INTO answers VALUES (?, ?)", (username, question))
    conn.commit()

def update_score(username):
    cur.execute("UPDATE users SET score = score + 1 WHERE username=?", (username,))
    conn.commit()

# ---------------- UI ----------------
st.title("📝 Python Quiz Application")

menu = ["Login", "Register", "Quiz", "Leaderboard"]
choice = st.sidebar.selectbox("Menu", menu)

# ---------------- REGISTER ----------------
if choice == "Register":
    st.subheader("Create Account")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")

    if st.button("Register"):
        try:
            register_user(u, p)
            st.success("Registration successful!")
        except:
            st.error("Username already exists")

# ---------------- LOGIN ----------------
elif choice == "Login":
    st.subheader("Login")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")

    if st.button("Login"):
        if login_user(u, p):
            st.session_state["user"] = u
            st.success("Login successful!")
        else:
            st.error("Invalid credentials")

# ---------------- QUIZ ----------------
elif choice == "Quiz":
    if "user" not in st.session_state:
        st.warning("Please login first")
    else:
        st.subheader("Quiz")
        user = st.session_state["user"]

        for q, opts in questions.items():
            if not answered(user, q):
                ans = st.radio(q, opts[:-1], key=q)
                if st.button(f"Submit {q}"):
                    save_answer(user, q)
                    if ans == opts[-1]:
                        update_score(user)
                        st.success("Correct!")
                    else:
                        st.error("Incorrect!")
                break
        else:
            st.info("Quiz completed!")

# ---------------- LEADERBOARD ----------------
elif choice == "Leaderboard":
    st.subheader("🏆 Leaderboard")
    cur.execute("SELECT username, score FROM users ORDER BY score DESC")
    data = cur.fetchall()
    st.table(data)

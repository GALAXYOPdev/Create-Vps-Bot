import sqlite3
import os

DB_PATH = "data/galaxy.db"

def init_database():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS containers (
            user_id TEXT,
            container_id TEXT,
            ssh_session TEXT,
            token TEXT,
            ram INTEGER,
            cpu INTEGER,
            os TEXT,
            PRIMARY KEY (user_id, container_id)
        )
    """)
    conn.commit()
    conn.close()

def add_to_database(user_id, container_id, ssh_session, token, ram, cpu, os):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO containers (user_id, container_id, ssh_session, token, ram, cpu, os) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, container_id, ssh_session, token, ram, cpu, os)
    )
    conn.commit()
    conn.close()

def count_user_servers(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM containers WHERE user_id = ?", (user_id,))
    count = cursor.fetchone()[0]
    conn.close()
    return count

def get_user_containers(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT container_id, ssh_session, token, ram, cpu, os FROM containers WHERE user_id = ?", (user_id,))
    containers = cursor.fetchall()
    conn.close()
    return containers

def get_container_by_token(token):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, container_id FROM containers WHERE token = ?", (token,))
    container = cursor.fetchone()
    conn.close()
    return container

def delete_container(user_id, container_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM containers WHERE user_id = ? AND container_id = ?", (user_id, container_id))
    conn.commit()
    conn.close()

def delete_all_containers():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM containers")
    conn.commit()
    conn.close()
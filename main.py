import datetime
import sqlite3
import secrets
from flask import Flask, request, jsonify, g, send_file
from argon2 import PasswordHasher
from email_validator import validate_email, EmailNotValidError
from argon2.exceptions import VerifyMismatchError
from sqlite3 import IntegrityError
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect("database.db")
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db
ph = PasswordHasher()
app = Flask(__name__)
connection = sqlite3.connect("database.db")
cursor = connection.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS players (id INTEGER PRIMARY KEY AUTOINCREMENT,token TEXT UNIQUE,username TEXT UNIQUE,origname text UNIQUE,password TEXT,email TEXT)")
cursor.execute("CREATE TABLE IF NOT EXISTS field (id INTEGER PRIMARY KEY,X INTEGER,Y INTEGER,FOREIGN KEY(id) REFERENCES players(id))")
connection.commit()
connection.close()
@app.post("/api")
def api():
    data = request.get_json()
    if type(data) == list and len(data) > 1:
        db = get_db()
        with db:
            cursor = db.cursor()
            if data[0] == "players":
                try:
                    if data[1] == "insert":
                        if type(data[4]) != str:
                            return jsonify({"error":"Invalid request"}),400
                        try:
                            email = validate_email(data[4],check_deliverability=True)
                        except EmailNotValidError:
                            return jsonify({"error":"Invalid request"}),400
                        data[4] = email.normalized
                        if type(data[3]) != str:
                            return jsonify({"error":"Invalid request"}),400
                        while True:
                            token = secrets.token_hex(16)
                            cursor.execute("SELECT token FROM players")
                            tokens = cursor.fetchall()
                            if not (token,) in tokens:
                                break
                        cursor.execute("SELECT * FROM players")
                        dbs = cursor.fetchall()
                        if dbs == []:
                            cursor.execute("INSERT INTO players (id,token,username,origname,password,email) VALUES(?,?,?,?,?,?) ON CONFLICT(username) DO NOTHING",(0,token,str(data[2]),str(data[2]),ph.hash(data[3]),data[4]))
                        else:
                            cursor.execute("INSERT INTO players (token,username,origname,password,email) VALUES(?,?,?,?,?) ON CONFLICT(username) DO NOTHING",(token,str(data[2]),str(data[2]),ph.hash(data[3]),data[4]))
                        if cursor.rowcount == 0:
                            return jsonify({"ok":"busy"}),409
                        else:
                            cursor.execute("INSERT INTO field (id,X,Y) VALUES(?,?,?)",(cursor.lastrowid,0,0))
                            return jsonify({"ok":token}),201
                    else:
                        cursor.execute("SELECT id FROM players WHERE token = ?",(data[2],))
                        pid = cursor.fetchone()
                        if not pid is None:
                            pid = pid[0]
                        else:
                            if data[1] != "verify":
                                return jsonify({"error":"Invalid request"}),400
                        if data[1] == "delete":
                            cursor.execute("DELETE FROM players WHERE id = ?",(pid,))
                            if cursor.rowcount == 0:
                                return jsonify({"error":"Invalid request"}),400
                            else:
                                return jsonify(["ok"]),200
                        elif data[1] == "update":
                            if len(data) == 6:
                                if data[4] == "username":
                                    now = datetime.datetime.now()
                                    if now.month == 4 and now.day == 1:
                                        cursor.execute("SELECT origname FROM players")
                                        orignames = cursor.fetchall()
                                        if not (data[5],) in orignames:
                                            try:
                                                cursor.execute("UPDATE players SET username = ? WHERE id = ?",(str(data[5]),pid))
                                                return jsonify({"ok":"vacant"}),200
                                            except IntegrityError:
                                                return jsonify({"ok":"busy"}),409
                                        else:
                                            return jsonify({"error":"Forbidden"}),403
                                    else:
                                        cursor.execute("SELECT id FROM players WHERE token = ?",(data[3],))
                                        npid = cursor.fetchone()
                                        if not npid is None:
                                            if npid[0] == pid:
                                                try:
                                                    cursor.execute("UPDATE players SET username = ? WHERE id = ?",(str(data[5]),pid))
                                                    cursor.execute("UPDATE players SET origname = ? WHERE id = ?",(str(data[5]),pid))
                                                    return jsonify({"ok":"vacant"}),200
                                                except IntegrityError:
                                                    return jsonify({"ok":"busy"}),409
                                            else:
                                                return jsonify({"error":"Forbidden"}),403
                                        else:
                                            return jsonify({"error":"Invalid request"}),400
                                else:
                                    return jsonify({"error":"Invalid request"}),400
                            else:
                                if data[3] == "password":
                                    if type(data[4]) != str:
                                        return jsonify({"error":"Invalid request"}),400
                                    cursor.execute("UPDATE players SET password = ? WHERE id = ?",(ph.hash(data[4]),pid))
                                    return jsonify(["ok"]),200
                                elif data[3] == "email":
                                    if type(data[4]) != str:
                                        return jsonify({"error":"Invalid request"}),400
                                    try:
                                        email = validate_email(data[4],check_deliverability=False)
                                    except EmailNotValidError:
                                        return jsonify({"error":"Invalid request"}),400
                                    data[4] = email.normalized
                                    cursor.execute("UPDATE players SET email = ? WHERE id = ?",(data[4],pid))
                                    return jsonify(["ok"]),200
                                else:
                                    return jsonify({"error":"Invalid request"}),400
                        elif data[1] == "select":
                            if data[3] == "username":
                                cursor.execute("SELECT username FROM players WHERE id = ?",(pid,))
                                return jsonify({"ok":cursor.fetchone()}),200
                            elif data[3] == "email":
                                cursor.execute("SELECT email FROM players WHERE id = ?",(pid,))
                                return jsonify({"ok":cursor.fetchone()})
                            else:
                                return jsonify({"error":"Invalid request"}),400
                        elif data[1] == "verify":
                            cursor.execute("SELECT password FROM players WHERE username = ?",(data[2],))
                            pshash = cursor.fetchone()
                            try:
                                if not pshash is None:
                                    if type(pshash[0]) == str:
                                        ph.verify(pshash[0],data[3])
                                else:
                                    return jsonify({"error":"Invalid request"}),400
                                cursor.execute("SELECT token FROM players WHERE username = ?",(data[2],))
                                return jsonify({"ok":cursor.fetchone()}),200
                            except VerifyMismatchError:
                                return jsonify({"ok":None}),401
                        else:
                            return jsonify({"error":"Invalid request"}),400
                except IndexError:
                    return jsonify([0])
            elif data[0] == "field":
                try:
                    cursor.execute("SELECT id FROM players WHERE token = ?",(data[2],))
                    pid = cursor.fetchone()
                    if not pid is None:
                        pid = pid[0]
                        if data[1] == "select":
                            cursor.execute("SELECT players.username,field.X,field.Y FROM players JOIN field ON players.id = field.id WHERE players.id = ?",(pid,))
                            return jsonify({"ok":cursor.fetchall()}),200
                        elif data[1] == "update":
                            cursor.execute("UPDATE field SET X = ?, Y = ? WHERE id = ?",(data[3],data[4],pid))
                            return jsonify(["ok"]),200
                        else:
                            return jsonify({"error":"Invalid request"}),400
                    else:
                        return jsonify({"error":"Invalid request"}),400
                except IndexError:
                    return jsonify({"error":"Invalid request"}),400
            else:
                return jsonify({"error":"Invalid request"}),400
    else:
        return jsonify({"error":"Invalid request"}),400
@app.get("/favicon.ico")
def favicon():
    return send_file("Acorn.ico",mimetype="image/x-icon")
@app.get("/")
def index():
    return send_file("index.html",mimetype="text/html")
@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()
if __name__ == "__main__":
    app.run()
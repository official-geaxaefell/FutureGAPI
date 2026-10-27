import datetime
import os
import secrets
from contextlib import asynccontextmanager
import dotenv
from psycopg import IntegrityError
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool
from fastapi import FastAPI, Request, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, FileResponse
from argon2 import PasswordHasher
from email_validator import validate_email, EmailNotValidError
from argon2.exceptions import VerifyMismatchError
ph = PasswordHasher()
connections = {}
dotenv.load_dotenv(".env")
url = os.getenv("url")
pool = AsyncConnectionPool(conninfo=url, min_size=1, max_size=5, open=False)
@asynccontextmanager
async def lifespan(app: FastAPI):
    await pool.open(wait=True)
    async with pool.connection() as db:
        async with db.transaction():
            async with db.cursor() as cursor:
                await cursor.execute("CREATE TABLE IF NOT EXISTS players (id SERIAL PRIMARY KEY,token TEXT UNIQUE,username TEXT UNIQUE,origname TEXT UNIQUE,password TEXT,email TEXT,trust_in INTEGER,moneys INTEGER DEFAULT 1000)")
                await cursor.execute("CREATE TABLE IF NOT EXISTS chat (id SERIAL PRIMARY KEY,message TEXT,room_name TEXT,owner TEXT,FOREIGN KEY(owner) REFERENCES players(username))")
                await cursor.execute("CREATE TABLE IF NOT EXISTS sessions (id INTEGER,time TEXT,viewed BOOLEAN,trusted BOOLEAN,pid INTEGER,FOREIGN KEY(pid) REFERENCES players(id))")
                await cursor.execute("CREATE TABLE IF NOT EXISTS room_params (name TEXT UNIQUE,poses JSONB DEFAULT '{\"house\":{},\"trade\":{}}'::jsonb,owner TEXT,FOREIGN KEY(owner) REFERENCES players(username))")
                await cursor.execute("CREATE TABLE IF NOT EXISTS inventory (items JSONB,room_name TEXT,pid INTEGER,FOREIGN KEY(pid) REFERENCES players(id),FOREIGN KEY(room_name) REFERENCES room_params(name))")
    yield
    await pool.close()
async def get_db():
    async with pool.connection() as db:
        yield db
app = FastAPI(lifespan=lifespan)
@app.post("/pl")
async def pl(request: Request, db = Depends(get_db)):
        data = await request.json()
        if type(data) == list and len(data) > 1:
            async with db.transaction():
                async with db.cursor() as cursor:
                    try:
                        if data[0] == "insert":
                            if len(data) < 4:
                                return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                            if type(data[3]) != str:
                                return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                            try:
                                email = validate_email(data[3],check_deliverability=True)
                            except EmailNotValidError:
                                return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                            data[3] = email.normalized
                            if type(data[2]) != str:
                                return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                            if len(str(data[1])) > 2:
                                if all(i for i in str(data[1]).split("-")):
                                    result = all("A" <= c <= "Z" or "a" <= c <= "z" or "0" <= c <= "9" or c == "-" or c == " " for c in str(data[1]))
                                    if not result:
                                        return JSONResponse(content={"denied":"only latin"}, status_code=403)
                                    parts = str(data[1]).split()
                                    data[1] = " ".join(parts)
                                else:
                                    return JSONResponse(content={"denied":"Invalid hyphen-splitting"}, status_code=403)
                            else:
                                return JSONResponse(content={"denied":"too short username"}, status_code=403)
                            await cursor.execute("SELECT * FROM players")
                            while True:
                                token = secrets.token_hex(16)
                                try:
                                    async with db.transaction():
                                        async with db.cursor() as cursor:
                                            await cursor.execute("INSERT INTO players (token,username,origname,password,email,trust_in) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(username) DO NOTHING",(token,data[1],data[1],ph.hash(data[2]),data[3],7))
                                            if cursor.rowcount == 0:
                                                return JSONResponse(content={"ok":"busy"}, status_code=409)
                                            else:
                                                return JSONResponse(content={"ok":token}, status_code=201)
                                except IntegrityError:
                                    continue
                        else:
                            if len(data) < 2:
                                return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                            await cursor.execute("SELECT id FROM players WHERE token = %s",(data[1],))
                            pid = await cursor.fetchone()
                            if not pid is None or data[0] == "verify":
                                if not pid is None:
                                    pid = pid[0]
                            else:
                                return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                            if data[0] == "delete":
                                if len(data) != 2:
                                    return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                                await cursor.execute("DELETE FROM players WHERE id = %s",(pid,))
                                if cursor.rowcount == 0:
                                    return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                                else:
                                    return JSONResponse(content=["ok"], status_code=200)
                            elif data[0] == "update":
                                if len(data) == 5:
                                    if data[3] == "username":
                                        if len(str(data[4])) > 2:
                                            if all(i for i in str(data[4]).split("-")):
                                                result = all("A" <= c <= "Z" or "a" <= c <= "z" or "0" <= c <= "9" or c == "-" or c == " " for c in str(data[4]))
                                                if not result:
                                                    return JSONResponse(content={"denied":"only latin"}, status_code=403)
                                                parts = str(data[4]).split()
                                                data[4] = " ".join(parts)
                                            else:
                                                return JSONResponse(content={"denied":"Invalid hyphen-splitting"}, status_code=403)
                                        else:
                                            return JSONResponse(content={"denied":"too short username"}, status_code=403)
                                        now = datetime.datetime.now()
                                        if now.month == 4 and now.day == 1:
                                            await cursor.execute("SELECT origname FROM players")
                                            orignames = await cursor.fetchall()
                                            if not (data[4],) in orignames:
                                                try:
                                                    async with db.transaction():
                                                        await cursor.execute("UPDATE players SET username = %s WHERE id = %s",(data[4],pid))
                                                    return JSONResponse(content={"ok":"vacant"}, status_code=200)
                                                except IntegrityError:
                                                    return JSONResponse(content={"ok":"busy"}, status_code=409)
                                            else:
                                                return JSONResponse(content={"denied":"tokens doesn't match"}, status_code=403)
                                        else:
                                            await cursor.execute("SELECT id FROM players WHERE token = %s",(data[2],))
                                            npid = await cursor.fetchone()
                                            if not npid is None:
                                                if npid[0] == pid:
                                                    try:
                                                        async with db.transaction():
                                                            await cursor.execute("UPDATE players SET username = %s WHERE id = %s",(data[4],pid))
                                                            await cursor.execute("UPDATE players SET origname = %s WHERE id = %s",(data[4],pid))
                                                        return JSONResponse(content={"ok":"vacant"}, status_code=200)
                                                    except IntegrityError:
                                                        return JSONResponse(content={"ok":"busy"}, status_code=409)
                                                else:
                                                    return JSONResponse(content={"error":"Forbidden"}, status_code=403)
                                            else:
                                                return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                                    else:
                                        return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                                elif len(data) == 4:
                                    if data[2] == "password":
                                        if type(data[3]) != str:
                                            return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                                        await cursor.execute("UPDATE players SET password = %s WHERE id = %s",(ph.hash(data[3]),pid))
                                        return JSONResponse(content=["ok"], status_code=200)
                                    elif data[2] == "email":
                                        if type(data[3]) != str:
                                            return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                                        try:
                                            email = validate_email(data[3],check_deliverability=False)
                                        except EmailNotValidError:
                                            return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                                        data[3] = email.normalized
                                        await cursor.execute("UPDATE players SET email = %s WHERE id = %s",(data[3],pid))
                                        return JSONResponse(content=["ok"], status_code=200)
                                    else:
                                        return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                                else:
                                    return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                            elif data[0] == "select":
                                if len(data) != 3:
                                    return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                                if data[2] == "username":
                                    await cursor.execute("SELECT username FROM players WHERE id = %s",(pid,))
                                    return JSONResponse(content={"ok":await cursor.fetchone()}, status_code=200)
                                elif data[2] == "email":
                                    await cursor.execute("SELECT email FROM players WHERE id = %s",(pid,))
                                    return JSONResponse(content={"ok":await cursor.fetchone()})
                                else:
                                    return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                            elif data[0] == "verify":
                                await cursor.execute("SELECT password FROM players WHERE username = %s",(data[1],))
                                pshash = await cursor.fetchone()
                                try:
                                    if not pshash is None:
                                        if type(pshash[0]) == str and type(data[2]) == str:
                                            ph.verify(pshash[0],data[2])
                                        else:
                                            return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                                        await cursor.execute("SELECT id FROM players WHERE username = %s",(data[1],))
                                        pid = await cursor.fetchone()
                                        await cursor.execute("SELECT MAX(id) FROM sessions WHERE pid = %s",(pid[0],))
                                        ssids = await cursor.fetchone()
                                        if ssids is None:
                                            await cursor.execute("INSERT INTO sessions (id,time,viewed,trusted,pid) VALUES (%s,%s,%s,%s,%s)",(0,datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S"),False,False,pid[0]))
                                        else:
                                            await cursor.execute("INSERT INTO sessions (id,time,viewed,trusted,pid) VALUES (%s,%s,%s,%s,%s)",(ssids[0]+1,datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S"),False,False,pid[0]))
                                        await cursor.execute("SELECT token FROM players WHERE username = %s",(data[1],))
                                        return JSONResponse(content={"ok":await cursor.fetchone()}, status_code=200)
                                    else:
                                        return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                                except VerifyMismatchError:
                                        return JSONResponse(content={"ok":None}, status_code=401)
                            else:
                                return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                    except IndexError:
                        return JSONResponse(content={"error":"Invalid request"}, status_code=400)
        else:
            return JSONResponse(content={"error":"Invalid request"}, status_code=400)
@app.post("/ss")
async def ss(request: Request, db = Depends(get_db)):
        data = await request.json()
        async with db.transaction():
            async with db.cursor() as cursor:
                if data[0] == "select":
                    if data[1] == "new":
                        await cursor.execute("SELECT id FROM players WHERE token = %s",(data[2],))
                        pid = await cursor.fetchone()
                        if not pid is None:
                            pid = pid[0]
                            await cursor.execute("SELECT time FROM sessions WHERE pid = %s AND trusted = %s AND viewed = %s",(pid,False,False))
                            sessions = await cursor.fetchall()
                            for x in sessions:
                                DMY = x[0].split()[0].split(".")
                                DMY = int(DMY[0]) + int(DMY[1]) * 30 + int(DMY[2]) * 365
                                await cursor.execute("SELECT trust_in FROM players WHERE id = %s",(pid,))
                                now = datetime.datetime.now()
                                shelf_life = await cursor.fetchone()
                                if now.minute + now.month * 30 + now.year * 365 - DMY >= shelf_life[0]:
                                    await cursor.execute("DELETE FROM sessions WHERE time = %s",(DMY,))
                            await cursor.execute("SELECT * FROM sessions WHERE pid = %s AND trusted = %s AND viewed = %s",(pid,False,False))
                            return JSONResponse(content={"ok":await cursor.fetchall()}, status_code=200)
                        else:
                            return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                    else:
                        await cursor.execute("SELECT id FROM players WHERE token = %s",(data[1],))
                        pid = await cursor.fetchone()
                        if not pid is None:
                            pid = pid[0]
                            await cursor.execute("SELECT time FROM sessions WHERE pid = %s AND id = %s",(pid,data[2]))
                            session = await cursor.fetchone()
                            if not session is None:
                                DMY = session[0].split()[0].split(".")
                                DMY = int(DMY[0]) + int(DMY[1]) * 30 + int(DMY[2]) * 365
                                await cursor.execute("SELECT trust_in FROM players WHERE id = %s",(pid,))
                                now = datetime.datetime.now()
                                if now.minute + now.month * 30 + now.year * 365 - DMY >= await cursor.fetchone():
                                    await cursor.execute("DELETE FROM sessions WHERE time = %s",(DMY,))
                                await cursor.execute("SELECT * FROM sessions WHERE pid = %s AND id = %s",(pid,data[2]))
                                return JSONResponse(content={"ok":await cursor.fetchone()}, status_code=200)
                            else:
                                return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                elif data[0] == "trust":
                    await cursor.execute("SELECT id FROM players WHERE token = %s",(data[1],))
                    pid = await cursor.fetchone()
                    if not pid is None:
                        pid = pid[0]
                        await cursor.execute("UPDATE sessions SET trusted = %s WHERE pid = %s",(True,pid))
                        return JSONResponse(content=["ok"], status_code=200)
                    else:
                        return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                elif data[0] == "block":
                    await cursor.execute("SELECT id FROM players WHERE token = %s",(data[1],))
                    pid = await cursor.fetchone()
                    if not pid is None:
                        pid = pid[0]
                        await cursor.execute("DELETE FROM sessions WHERE pid = %s AND id = %s",(pid,data[2]))
                        return JSONResponse(content=["ok"], status_code=200)
                    else:
                        return JSONResponse(content={"error":"Invalid request"}, status_code=400)
                else:
                    return JSONResponse(content={"error":"Invalid request"}, status_code=400)
@app.websocket("/{token}/{room}")
async def cfl(websocket: WebSocket, token: str, room: str):
        async with pool.connection() as db:
            async with db.transaction():
                async with db.cursor() as cursor:
                    display = websocket.query_params.get("orient")
                    if display is None:
                        display = (1920,1080)
                    else:
                        display = display.split("x")
                        if len(display) != 2:
                            await websocket.close(code=1008, reason="Invalid orientation data format")
                            return
                        try:
                            display[0] = int(display[0])
                            display[1] = int(display[1])
                        except ValueError:
                            await websocket.close(code=1008, reason="Invalid orientation data format")
                            return
                    await cursor.execute("SELECT username FROM players WHERE token = %s",(token,))
                    name = await cursor.fetchone()
                    if name is None:
                        await websocket.close(code=1008, reason="user with token doesn't exist")
                        return
                    else:
                        name = name[0]
                    await cursor.execute("SELECT * FROM room_params WHERE name = %s",(room,))
                    _Room = await cursor.fetchone()
                    if _Room is None:
                        await websocket.close(code=1008, reason="room doesn't exist")
                        return
                    await cursor.execute("SELECT poses FROM room_params WHERE name = %s",(room,))
                    _Poses = await cursor.fetchone()
                    _Poses = _Poses[0]
                    if not name in _Poses["house"]:
                        poses = websocket.query_params.get("poses")
                        if poses is None:
                            await websocket.close(code=1008, reason="poses is undefined")
                            return
                        poses = poses.split(",")
                        if len(poses) != 4:
                            await websocket.close(code=1008, reason="Invalid new poses's structure")
                            return
                        try:
                            poses[0] = int(poses[0])
                            poses[1] = int(poses[1])
                            poses[2] = int(poses[2])
                            poses[3] = int(poses[3])
                        except ValueError:
                            await websocket.close(code=1008, reason="Invalid new poses's structure")
                            return
                        _Poses["house"][name] = (poses[0],poses[1])
                        _Poses["trade"][name] = (poses[2],poses[3])
                        await cursor.execute("UPDATE room_params SET poses = %s WHERE name = %s",(Jsonb(_Poses),room))
                    connections.setdefault(room,{})
                    connections[room][name] = {"websocket":websocket,"x":_Poses["house"][name][0],"y":_Poses["house"][name][1],"display":display}
                    await websocket.accept()
                    await cursor.execute("SELECT * FROM chat WHERE room_name = %s ORDER BY id DESC LIMIT 5",(room,))
                    last_msg = await cursor.fetchall()
                    if last_msg != []:
                        last = last_msg[0][0]
                    await websocket.send_json(last_msg)
                    for x in connections[room].keys():
                        if connections[room][x]["websocket"] != websocket:
                            await connections[room][x]["websocket"].send_text(f"{name} connected")
        try:
            while True:
                data = await websocket.receive_json()
                if type(data) == list and len(data) > 1:
                    async with pool.connection() as db:
                        async with db.transaction():
                            async with db.cursor() as cursor:
                                if data[0] == "chat":
                                    if len(data) != 3:
                                        await websocket.send_json({"error":"Invalid format"})
                                        continue
                                    if data[1] == "send":
                                        await cursor.execute("INSERT INTO chat (message,room_name,owner) VALUES(%s,%s,%s)",(data[2],room,name))
                                        for x in connections[room].keys():
                                            if connections[room][x]["websocket"] != websocket:
                                                await connections[room][x]["websocket"].send_json({"message":[name,data[2]]})
                                    elif data[1] == "view":
                                       await cursor.execute("SELECT * FROM chat WHERE room_name = %s ",(room,name)) 
                                elif data[0] == "field":
                                    if len(data) != 3:
                                        await websocket.send_json({"error":"Invalid format"})
                                        continue
                                    if type(data[1]) != int or type(data[2]) != int:
                                        await websocket.send_json({"error":"Invalid format"})
                                        continue
                                    connections[room][name] = {"websocket":websocket,"x":data[1],"y":data[2],"display":display}
                                    for x in connections[room].keys():
                                        if connections[room][x]["websocket"] != websocket and abs(connections[room][name]["x"] - connections[room][x]["x"]) < connections[room][x]["display"][0] and abs(connections[room][name]["y"] - connections[room][x]["y"]) < connections[room][x]["display"][1]:
                                            await connections[room][x]["websocket"].send_json({name:[connections[room][name]["x"],connections[room][name]["y"]]})
                                    houses = tuple(_Poses["house"].values())
                                    owners = tuple(_Poses["house"].keys())
                                    for i in range(len(houses)):
                                        if abs(connections[room][name]["x"] - houses[i][0]) < display[0] and abs(connections[room][name]["y"] - houses[i][1]) < display[1]:
                                            await websocket.send_json({f"{owners[i]}'s house":(houses[i][0],houses[i][1])})
                                    shops = tuple(_Poses["trade"].values())
                                    owners = tuple(_Poses["trade"].keys())
                                    for i in range(len(shops)):
                                        if abs(connections[room][name]["x"] - shops[i][0]) < display[0] and abs(connections[room][name]["y"] - shops[i][1]) < display[1]:
                                            await websocket.send_json({f"{owners[i]}'s shop":(shops[i][0],shops[i][1])})
                                elif data[0] == "orient":
                                    if len(data) != 2:
                                        await websocket.send_json({"error":"Invalid format"})
                                        continue
                                    if type(data[1]) == str:
                                        new_display = data[1].split("x")
                                        if new_display != []:
                                            if len(new_display) != 2:
                                                await websocket.send_json({"error":"Invalid format"})
                                                continue
                                            try:
                                                new_display[0] = int(new_display[0])
                                                new_display[1] = int(new_display[1])
                                            except ValueError:
                                                await websocket.send_json({"error":"Invalid format"})
                                                continue
                                            display = new_display
                                            connections[room][name] = {"websocket":websocket,"x":connections[room][name]["x"],"y":connections[room][name]["y"],"display":display}
                                    else:
                                        await websocket.send_json({"error":"Invalid format"})
                                        continue
                else:
                    await websocket.send_json({"error":"Invalid format"})                  
        except WebSocketDisconnect:
            if room in connections:
                if name in connections[room]:
                    del connections[room][name]
                for x in connections[room].keys():
                    if connections[room][x]["websocket"] != websocket:
                        await connections[room][x]["websocket"].send_text(f"{name} disconnected")
@app.get("/favicon.ico")
async def favicon():
    return FileResponse("Acorn.ico", media_type="image/x-icon")
@app.get("/")
async def index():
    return FileResponse("index.html", media_type="text/html")
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=80)

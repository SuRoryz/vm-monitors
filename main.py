import subprocess
import asyncio
from qemu.qmp import QMPClient
from threading import Thread
import time
import math
import os
import re
import time
from flask import Flask, redirect, render_template, jsonify, request, send_file, session
from flask_session import Session
from flask_cors import CORS, cross_origin
from flask_socketio import SocketIO, emit, disconnect, join_room, leave_room, rooms
from flasgger import Swagger
from sql import DBHelper, db, User, VM
from sqlalchemy.sql import text
from sqlalchemy import or_, and_, not_
from werkzeug.utils import secure_filename
from qmp import QEMUMonitorProtocol
import cv2 
from glob import glob
from uuid import uuid4
import paramiko

app = Flask(__name__, static_folder='./build', static_url_path='/')
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SECRET_KEY'] = 'secret!'
app.config['SESSION_TYPE'] = 'filesystem'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config["UPLOAD_FOLDER"] = "./build/files/"
ALLOWED_EXTENSIONS = ["jpg", "jpeg", "png", "jfif"]

Session(app)
db.init_app(app)
swagger = Swagger(app)

cors = CORS(app, supports_credentials=True)
socketio = SocketIO(app=app, cors_allowed_origins='*')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
    return app.send_static_file('placeholder.jpg')

@app.errorhandler(404)
def not_found(e):
    return app.send_static_file('placeholder.jpg')

@app.route('/profile', methods=['GET'])
def profile():
    if DBHelper.authToken(session['token']):
        return app.send_static_file('index.html')
    return redirect('/login')

@app.route('/task/<id>', methods=['GET'])
def tour(id):
    if DBHelper.authToken(session['token']):
        return app.send_static_file('index.html')
    return redirect('/login')
@app.route('/api/login', methods=['POST'])
def login():
    """Используется для авторизации
    После успешной авторизации возвращается токен сессии в куки.
    ---
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              description: Имя пользователя
              type: string
              required: true
            password:
              description: Пароль
              type: string
              required: true
    definitions:
      components:
        securitySchemes:
          cookieAuth:
            type: apiKey
            in: cookie
            name: session
      security:
        - cookieAuth: []
    responses:
      200:
        description: Объект с сообщением и статусом запроса
        headers: 
            Set-Cookie:
              schema: 
                type: string
                example: session=abcde12345; Path=/; HttpOnly
        schema:
          type: object
          properties:
            message:
              description: Сообщение с информацией 
              type: string
            status:
              description: Статус исполнения запроса
              type: integer
        examples:
          {'message': 'string', 'status': 0}
    """

    data = request.json

    if not('username' in data and 'password' in data):
        return jsonify({'message': 'Укажите логин и пароль', 'status': 0})

    username = data['username']
    password = data['password']
    
    token, _ = DBHelper.authUser(username, password)

    if token:
        session['token'] = token
        res = jsonify({'message': 'Успешный вход', 'status': 1})
        res.headers.add('Access-Control-Allow-Origin', '*')
        return res
    
    return jsonify({'message': 'Ошибка входа', 'status': 0})

@app.route('/api/register', methods=['POST'])
def register():
    """Используется для регистрации
    После успешной регистрации редиректит на страницу логина
    ---
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              description: Имя пользователя
              type: string
              required: true
            password:
              description: Пароль
              type: string
              required: true
            role:
              description: Роль. Организатор не может учавствовать в турнире, а участники не могут их организовать
              type: string
              required: true
              enum: ['org', 'user']
    responses:
      200:
        description: Объект с сообщением и статусом запроса
        schema:
          type: object
          properties:
            message:
              description: Сообщение с информацией 
              type: string
            status:
              description: Статус исполнения запроса
              type: integer
        examples:
          {'message': 'string', 'status': 0}
    """

    data = request.json

    if not('username' in data and 'password' in data and 'role' in data) or (
        len(data['username']) < 4 or len(data['password']) < 4 or data['role'] not in ['org', 'user']):
        return jsonify({'message': 'Укажите логин и пароль', 'status': 0})

    username = data['username']
    password = data['password']
    role = data['role']

    status = DBHelper.createUser(username, password, role)

    if status:
        return jsonify({'message': 'Успешная регистрация', 'status': 1})
    else:
        return jsonify({'message': 'Ошибка регистрации', 'status': 0})

class Timer(Thread):
    def __init__(self, func, args, interval) -> None:
        Thread.__init__(self)
        self.func = func
        self.args = args
        self.interval = interval
        self.running = True
    
    def run(self):
        while self.running:
            self.func(*self.args)
            time.sleep(self.interval)

class SubProccesRunner(Thread):
    def __init__(self) -> None:
        Thread.__init__(self)
        self.queue = []
    
    def run(self):
        while True:
            if self.queue:
                command = self.queue.pop(0)
                q = Thread(target = lambda: subprocess.Popen(command))
                q.start()

            time.sleep(0.1)

class Client:
    def __init__(self, name: str, ip, socket: int):
        self.qmp = QMPClient(name)
        self.socket = socket
        self.ip = ip

    async def watch_events(self):
        try:
            async for event in self.qmp.events:
                print(f"Event: {event['event']}")
        except asyncio.CancelledError:
            return

    async def run(self, address):
        await self.qmp.connect((self.ip, self.socket))

        asyncio.create_task(self.watch_events())
        await self.qmp.runstate_changed()
        await self.disconnect()

TIMERS = {

}
QMP_CLIENTS = {
    
}

@app.route('/api/vm/createVM/<name>/<os>', methods=['POST'])
def create_vm(name, os):
    if user := DBHelper.authToken(session['token']):
        data = request.json

        DBHelper.createVM(name, user.id, os, data["ip"], data["port"], ssh=False, ip_qmp=data["ip_qmp"], path=data["path"], vm_type=data["vm_type"])
        socketio.emit("ping", rooms=["/vms"])

        return jsonify({'message': 'Успех', 'status': 1})

    return redirect('/login')


@app.route('/api/vm/addVM/<name>/<os_>', methods=['POST'])
def add_vm(name, os_):
    if user := DBHelper.authToken(session['token']):
        data = request.json
        
        if not ('ip' in data):
            return jsonify({'message': 'Укажите ip', 'status': 0})

        if not ('port' in data):
            return jsonify({'message': 'Укажите port', 'status': 0})
        
        if "ssh" in data:
            ssh = data["ssh"]
        else:
            ssh = False
        
        if ssh:
            vm = DBHelper.createVM(data["name"], user.id, os_, data["ip"], int(data["port"]), True, data["ssh_user"], data["ssh_password"], ip_qmp=data["ip_qmp"], path=data["path"], vm_type=data["vm_type"])
        else:
            vm = DBHelper.createVM(data["name"], user.id, os_, data["ip"], int(data["port"]), False, ip_qmp=data["ip_qmp"], path=data["path"], vm_type=data["vm_type"])

        cl = QEMUMonitorProtocol((vm.ip, vm.socket))

        QMP_CLIENTS[str(id)] = {
            "client": cl,
            "VM": vm
        }

        print(vm.ip, vm.socket)

        try:
            cl.connect()
            status = cl.cmd("query-status")
            vm.running = status["return"]["status"] == "running"
            print(status)

            filename = "./build/dumps/" + str(vm.id) + "last_dump"
                
            res = cl.cmd("screendump", {"filename": filename})
            cwd = os.getcwd()
            input_dir = os.path.join(cwd, filename)    
            ppm = glob(input_dir)[0]

            cv2.imwrite(str(filename)+".png", cv2.imread(ppm))

            vm.last_dump = filename
            db.session.commit()

            cl.close()
        except Exception as e:
            print(e)
            pass

        socketio.emit("ping", rooms=["/vms"])

        return jsonify({'message': 'Успех', 'status': 1})    

    return redirect('/login')

@app.route('/api/vm/deleteVM/<id>', methods=['POST'])
def delete_vm(id):
    if user := DBHelper.authToken(session['token']):
        if vm := VM.query.get(id):
            if VM.owner == user.id:
                DBHelper.deleteVM(id)

                socketio.emit("ping", rooms=["/vms"])

                return jsonify({'message': 'Успех', 'status': 1})

    return redirect('/login')

@app.route('/api/vm/getAll', methods=['POST'])
def get_all_vms():
    if user := DBHelper.authToken(session['token']):
        data = request.json

        VMs = VM.query.filter(VM.owner == user.id).order_by(
            text(
            f"{'deadline' if data['sort_by'] == 'date' else 'name'} {'desc' if data['order'] == 'desc' else 'asc'}"
            )
        ).filter(
            VM.name.contains(data['query'])
        )

        if data['os'] != "all":
            VMs = VMs.filter(
                VM.os == data['os']
            )
        
        if data['status'] != "all":
            VMs = VMs.filter(
                VM.running == data['status']
            )

        all_records = len(VMs.all())
        VMs = VMs.paginate(page=data['page'], error_out=False, max_per_page=data['count'])

        if VMs:
            return jsonify({'message': 'Успех', 'status': 1, "vms": [{
                "id": vm.id,
                "name": vm.name,
                "os": vm.os,
                "last_dump": "dumps/" + str(vm.id) + "last_dump.png",
                "running": vm.running
            } for vm in VMs] })
        
        return jsonify({'message': 'Ошибка', 'status': 0})

@app.route('/api/vm/run/<id>', methods=['POST'])
def run_vm(id):
    global TIMERS

    if user := DBHelper.authToken(session['token']):
        if vm := VM.query.get(id):
            if vm.owner == user.id:
                if vm.ssh:
                    run_on_another(vm.ip, vm.socket, vm.ssh_pass, vm.ssh_user, ip_qmp=vm.ip_qmp, path=vm.path, vm_type=vm.vm_type)
                else:
                    pc.queue.append(run_qemu(vm.socket, ip_qmp=vm.ip_qmp, path=vm.path, vm_type=vm.vm_type))

                def updateScreen():
                    global QMP_CLIENTS
                    if str(id) in QMP_CLIENTS:
                        try:
                            cl = QMP_CLIENTS[str(id)]["client"]
                            filename = os.path.dirname(os.path.abspath(__file__)) + "\\build\\dumps\\" + str(id) + "last_dump"
                    
                            res = cl.cmd("screendump", {"filename": filename})
                            cwd = os.getcwd()
                            input_dir = os.path.join(cwd, filename)    
                            ppm = glob(input_dir)[0]

                            cv2.imwrite(str(filename)+".png", cv2.imread(ppm))
                        except:
                            pass
                
                TIMERS[str(id)] = Timer(updateScreen, [], 5)
                TIMERS[str(id)].start()

                vm.running = True
                db.session.commit()

                socketio.emit("ping", rooms=["/vms"])

                return jsonify({'message': 'VM started', 'status': 1})

@app.route('/api/vm/stop/<id>', methods=['POST'])
def stop_vm(id):
    if user := DBHelper.authToken(session['token']):
        if vm := VM.query.get(id):
            if vm.owner == user.id:
                global QMP_CLIENTS

                if str(id) in QMP_CLIENTS:
                    cl = QMP_CLIENTS[str(id)]["client"]
                    res = cl.cmd("quit")
                else:
                    try:
                        cl = QEMUMonitorProtocol((vm.ip, vm.socket))
                        cl.connect()
                        cl.cmd("quit")
                        cl.close()
                    except:
                        pass

                vm.running = True
                db.session.commit()

                if str(id) in TIMERS:
                    TIMERS[str(id)].running = False
                
                if str(id) in QMP_CLIENTS:
                    QMP_CLIENTS[str(id)]["client"].close()
                
                if str(id) in QMP_CLIENTS:
                    del QMP_CLIENTS[str(id)]

                vm.running = False
                db.session.commit()

                socketio.emit("ping", rooms=["/vms"])

                return jsonify({'message': 'VM stopped', 'status': 1})
    
    return jsonify({'message': 'VM started', 'status': 0})

@app.route('/api/vm/hook/<id>', methods=['POST'])
def hook_vm(id):
    if user := DBHelper.authToken(session['token']):
        if vm := VM.query.get(id):
            if vm.owner == user.id:
                global QMP_CLIENTS
                cl = QEMUMonitorProtocol((vm.ip, int(vm.socket)))
                print(vm.ip, vm.socket)

                QMP_CLIENTS[str(id)] = {
                    "client": cl,
                    "VM": vm
                }

                cl.connect()
                return jsonify({'message': 'VM started', 'status': 1})

@app.route('/api/vm/getInfo/<id>', methods=['POST'])
def info_vm(id):
    if user := DBHelper.authToken(session['token']):
        if vm := VM.query.get(id):
            if vm.owner == user.id:
                global QMP_CLIENTS
                cl = QMP_CLIENTS[str(vm.id)]["client"]
                res = cl.cmd("query-status")

                return jsonify({'message': 'VM started', 'status': 1, 'result': res})

@app.route('/api/vm/getScreen/<id>', methods=['POST'])
def screen_vm(id):
    if user := DBHelper.authToken(session['token']):
        if vm := VM.query.get(id):
            if vm.owner == user.id:
                global QMP_CLIENTS
                cl = QMP_CLIENTS[str(vm.id)]["client"]

                filename = "./build/dumps/" + uuid4().hex
                
                res = cl.cmd("screendump", {"filename": filename})
                cwd = os.getcwd()
                input_dir = os.path.join(cwd, filename)    
                ppm = glob(input_dir)[0]

                cv2.imwrite(str(filename)+".png", cv2.imread(ppm))

                return jsonify({'message': 'VM started', 'status': 1, 'result': filename})


def run_on_another(ip, port, password=None, login=None, keyfile=None, ip_qmp="0.0.0.0", vm_type="qemu", path="ubuntu.iso"):
    if vm_type == "qemu":
        command = ['echo', f'"{password}" |' 'sudo -S', 'qemu-system-x86_64', '-nographic', '-cdrom', path, "-qmp", f"tcp:{ip_qmp}:{port},server=on,wait=off" ]
    elif vm_type == "docker":
        command = ['echo', f'"{password}" |' 'sudo -S', 'docker', 'run', path]
        
    if login:
        ssh = paramiko.SSHClient()
        print(login, password)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=login, password=password)
        print(" ".join(command))
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(" ".join(command),  get_pty=True)
    elif keyfile:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, key_filename=keyfile)
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(" ".join(command),  get_pty=True)

    return command

def run_qemu(socket, ip_qmp="0.0.0.0", vm_type="qemu", path="ubuntu.iso"):

    if vm_type == "qemu":
        command = ['qemu-system-x86_64', '-nographic', '-cdrom', path, "-qmp", f"tcp:{ip_qmp}:{socket},server=on,wait=off"]
    elif vm_type == "docker":
        command = ['docker', 'run', path]
        
    return command

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    pc = SubProccesRunner()
    pc.start()

    socketio.run(app)

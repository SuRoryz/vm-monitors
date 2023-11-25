from json import loads, dumps
import sqlite3
import random
import uuid
import time

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Boolean, event, func
from sqlalchemy_events import listen_events, on

from datetime import datetime

import math
import more_itertools as mit

from flask_socketio import SocketIO, emit

class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)

class User(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, default='user', nullable=False)

    def __repr__(self) -> str:
        return f"<User {self.id} {self.username} {self.role} {self.team_id}>"

class AuthToken(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    token: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    user_id: Mapped[int] = db.Column(Integer, db.ForeignKey('user.id'), nullable=False)
    user: Mapped['User'] = db.relationship('User')

class UserVM(db.Model):
    __tablename__ = 'user_vms'
    id = db.Column(db.Integer, primary_key=True)
    user_id: Mapped[int] = db.Column(Integer, db.ForeignKey('user.id'), nullable=False)
    task_id: Mapped[int] = db.Column(Integer, db.ForeignKey('vm.id'), nullable=False)

class VM(db.Model, ):
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner: Mapped[int] = mapped_column(Integer, nullable=True)
    os: Mapped[str] = mapped_column(String, nullable=True, default="ubuntu")
    socket: Mapped[int] = mapped_column(Integer, nullable=True)
    ip: Mapped[str] = mapped_column(String, nullable=True)
    ssh: Mapped[bool] = mapped_column(Boolean, nullable=True)
    ip_qmp: Mapped[str] = mapped_column(String, nullable=True)
    path: Mapped[str] = mapped_column(String, nullable=True)
    vm_type: Mapped[str] = mapped_column(String, nullable=True)

    ssh_pass: Mapped[str] = mapped_column(String, nullable=True)
    ssh_user: Mapped[str] = mapped_column(String, nullable=True)

    last_dump: Mapped[str] = mapped_column(String, nullable=True)
    users = db.relationship('User', secondary=UserVM.__table__, backref='vms')

    name: Mapped[str] = mapped_column(String, nullable=True, default="0:0")
    running: Mapped[bool] = mapped_column(Boolean, default=False)

    def __repr__(self) -> str:
        return (f"<Match {self.id} TOURNAMENT:  AGREED DONE: {self.done} |"
                f" | PHASE: {self.phase} | Users: {[user.id for user in self.users]}>"
        )

class DBHelper:
    db = db

    @classmethod
    def authToken(cls, token):
        token = cls.db.session.query(AuthToken).filter_by(token=token).first()

        if not token:
            return False
        
        if datetime.timestamp(token.created_at) + 3600 > int(time.time()):
            db.session.delete(token)
            db.session.commit()
            return None
        
        return token.user
    
    @classmethod
    def deleteToken(cls, user):
        cls.db.session.query(AuthToken).filter_by(user_id=user.id).delete()
        cls.db.session.commit()

    @classmethod
    def authUser(cls, username, password):
        user = User.query.filter(func.lower(User.username) == username.lower()).first()

        if user and user.password == password:
            token = str(uuid.uuid4())
            cls.db.session.add(AuthToken(token=token, user_id=user.id))
            cls.db.session.commit()
            return token, user.id
        
        return None, None

    @classmethod
    def createUser(cls, username, password, role):
        user = cls.db.session.query(User).filter_by(username=username).first()

        if user:
            return False
        
        user = User(username=username, password=password, role=role)

        cls.db.session.add(user)
        cls.db.session.commit()

        return True
    
    @classmethod
    def createTeam(cls, name, user):
        team = cls.db.session.query(Team).filter_by(name=name).first()

        if team:
            return False
        
        team = Team(name=name, cap=user.id)
        
        cls.db.session.add(team)
        cls.db.session.commit()

        user.team_id = team.id

        print('TD', user.team_id)

        cls.db.session.commit()

        return True

    @classmethod
    def addInTeam(cls, team, user):
        team.addUser(user)
    
    @classmethod
    def createTask(cls, user, team_id, deadline, headline, text, task_type="task", with_chat=False, with_files=True, start=0):
        team1 = cls.db.session.query(Team).filter_by(id=team_id).first()

        if not(team1):
            return False

        task = Task(owner=user.id, team=[team1], deadline=deadline, headline=headline, text=text, task_type=task_type, with_chat=with_chat, with_files=with_files, start=start)

        cls.db.session.add(task)
        cls.db.session.commit()

        task.createStartPhases()

        return True
    
    @classmethod
    def createInvite(cls, userId, teamId, ownerId):
        invite = Invite(user_id=userId, team_id=teamId, owner_id = ownerId)
        cls.db.session.add(invite)

        cls.db.session.commit()

        return True

    @classmethod
    def addToTask(cls, task_id, user_id):
        user = cls.db.session.query(User).filter_by(id=user_id).first()
        task = cls.db.session.query(Task).filter_by(id=task_id).first()

        task.users.append(user)

        cls.db.session.commit()
    
    @classmethod
    def removeFromTask(cls, task_id, user_id):
        user = cls.db.session.query(User).filter_by(id=user_id).first()
        task = cls.db.session.query(Task).filter_by(id=task_id).first()

        task.users.remove(user)

        cls.db.session.commit()
    
    @classmethod
    def updateTask(cls, task_id, text, headline, deadline, phase, phases, start):
        task = cls.db.session.query(Task).filter_by(id=task_id).first()

        task.deadline = deadline
        task.text = text
        task.headline = headline
        task.phase = phase
        task.start = start

        if phase >= len(phases):
            task.done = True
        
        for phase in task.phases:
            cls.db.session.query(TaskPhase).filter_by(id=phase.id).delete()
        
        q = []
        for phase in phases:
            q.append(TaskPhase(text=phase["text"], deadline=phase["deadline"], done=phase["done"], by=phase["by"]))

        task.phases = q

        cls.db.session.commit()

    @classmethod
    def deleteVM(cls, id):
        cls.db.session.query(VM).filter_by(id=id).delete()
        cls.db.session.commit()

    @classmethod
    def createVM(cls, name, owner, os, ip, socket, ssh, ssh_user=None, ssh_password=None, ip_qmp=None, path=None, vm_type=None):

        if ssh:
            vm = VM(name=name, owner=owner, os=os, ip=ip, socket=socket, ssh=True, ssh_user=ssh_user, ssh_pass=ssh_password, ip_qmp=ip_qmp, path=path, vm_type=vm_type)
        else:
            vm = VM(name=name, owner=owner, os=os, ip=ip, socket=socket, ssh=False, ip_qmp=ip_qmp, path=path, vm_type=vm_type)

        cls.db.session.add(vm)
        cls.db.session.commit()

        vm.last_dump = "./build/dumps/" + str(vm.id) + "last_dump"
        cls.db.session.commit()

        return vm

    @classmethod
    def getTeam(cls, name):
        return cls.db.session.query(Team).filter_by(name=name).first()

    @classmethod
    def getVM(cls, socket):
        return cls.db.session.query(VM).filter_by(socket=socket).first()

    @classmethod
    def getVMs(cls, user_id):
        return cls.db.session.query(VM).filter_by(owner=user_id).all()



    
            
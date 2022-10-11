# Tune - Created by Artucuno#1898
# https://tune.loona.gg

import time
import youtube_dl
import requests
import webbrowser
import json
import requests
from art import *
import pypresence
import sys, os
import zlib
from threading import Thread
from pynotifier import Notification
from PIL import Image
import time
import logging
import random
import string

import base64
from uuid import getnode
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

tprint("Tune Music")

class Security:
    def __init__(self):
        self.public_key = b'''
'''

    def _genKeys(self):
        """Generate Public and Private Keys"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open('private_key.pem', 'wb') as f:
            f.write(private_pem)

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open('public_key.pem', 'wb') as f:
            f.write(public_pem)

    def encrypt(self, data: bytes):
        """Encrypt Bytes"""
        public_key = serialization.load_pem_public_key(
            self.public_key,
            backend=default_backend()
        )
        encrypted = base64.b64encode(public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ))
        return encrypted

    def decrypt(self, data: bytes):
        """Decrypt Bytes"""
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        decrypted = private_key.decrypt(
            base64.b64decode(data),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

class App:
    def __init__(self):
        # Variables
        self.authors = [('Artucuno', 'https://artucuno.dev')]
        self.version = '1.0'
        self.API_ENDPOINT = 'https://tune.loona.gg/api/v1/'
        self.CLIENT_ID = '674866541346684938'
        self.auth = (False, None, 0)

        # Presence Clients
        self.c = pypresence.Client(self.CLIENT_ID)
        self.rpc = pypresence.Presence(self.CLIENT_ID)

        self.security = Security()

        self.pid = os.getpid()

    def _cf(self, folder: str):
        try:
            os.mkdir(folder)
        except:
            pass

    def _checks(self):
        self._cf('data')
        self._cf('data/cache')
        self._cf('data/history')
        self._cf('data/user')
        if self._checkForUpdate():
            print('The Tune App has an update! (It is recommended that you update.)\nhttps://github.com/Artucuno/Tune-App')
        try:
            self._downloadFile('http://tune.loona.gg/static/logo.png', 'logo.png')
        except:
            logger.warning('Unable to download Tune Logo')
        self.c.start()
        self.rpc.connect()

    def _checkForUpdate(self, timeout: int = 3):
        try:
            x = requests.get(self.API_ENDPOINT+'version', timeout=timeout)
            #print(x.text)
            #print(x.status_code)
            if str(x.text.strip()) == self.version:
                return False
            else:
                return True
        except Exception as e:
            print(e)
            return None

    def _downloadFile(self, url: str, location: str):
        """Download a file using request streaming"""
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(location, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        return location

    def _toICO(self, filename: str):
        """Convert an image to a .ICO"""
        img = Image.open(filename)
        img.save(filename.split('/')[-1].split('.')[0]+'.ico')
        return filename.split('.')[0]+'.ico'

    def event_activity_join(self, data):
        print('ACTIVITY_JOIN', data) # WIP

    def event_activity_join_request(self, data):
        print('ACTIVITY_JOIN_REQUEST', data) # WIP

    def thread_getSong(self, gid):
        while True:
            try:
                x = requests.post(self.API_ENDPOINT+'getsong', data={'guild': gid})
                l = x.json()
                for p in l['Config']:
                    if p['isplaying']:
                        t = f'Playing / Node: {p["node"]} ({p["debug"]["ping"]}ms)'
                        if p['ispaused']:
                            t = f'Paused / Node: {p["node"]} ({p["debug"]["ping"]}ms)'
                        self.c.set_activity(pid=int(self.pid),
                            state=p['trackdata']['author'],
                            details=p["trackdata"]["title"],
                            large_text="Tune Music",
                            large_image="{}".format(p['trackdata']['thumbnail']),
                            small_text=t,
                            small_image="tune",
                            buttons=[{"label": "Listen to song", "url": p['trackdata']['url']}, {"label": "Invite Tune", "url": "https://tune.loona.gg"}]
                        )
                    else:
                        self.c.clear_activity()
            except Exception as e:
                print(e)
                self.c.clear_activity()
            time.sleep(2)

    def _start(self):
        """Start the app"""
        self._checks() # Checks before Starting
        auth = self.start_auth()
        if auth: # Authenticated
            auth = auth['data']
            self.auth = (True, auth, auth['user']['id'])
            Notification(
            	title='Authenticated',
            	description='Welcome, {}!'.format(auth['user']['username']),
                icon_path=self._toICO(self._downloadFile(f'https://cdn.discordapp.com/avatars/{self.auth[2]}/{self.auth[1]["user"]["avatar"]}.jpg', 'avatar.jpg')),
            	duration=5,
            	urgency='normal'
            ).send()
            gid = input('Enter your server id >> ')
            Thread(target=lambda:self.thread_getSong(gid)).start()
        else: # Unauthenticated
            Notification(
            	title='Authenticated Failed',
            	description='Unable to authenticate (Make sure that you push Authorize!)',
            	duration=5,
            	urgency='normal'
            ).send()
        self.c.register_event('ACTIVITY_JOIN', self.event_activity_join)
        self.c.register_event('ACTIVITY_JOIN_REQUEST', self.event_activity_join_request)
        print(self.auth)

        while True:
            time.sleep(1)

    def start_auth(self):
        """Start authenticating - Opens Discord"""
        try:
            if os.path.isfile('auth'):
                try:
                    authd = self.c.authenticate(open('auth', 'r').read().strip())
                    return authd
                except:
                    pass
            auth = self.c.authorize(self.CLIENT_ID, ['identify', 'email', 'guilds'])
            code_grant = auth['data']['code']

            token = requests.post(self.API_ENDPOINT+'exchange_code', data={'code': str(code_grant)})
            authd = self.c.authenticate(token.json()['access_token'])
            open('auth', 'w+').write(token.json()['access_token'])
            return authd
        except Exception as e:
            print(e)
            return False

#Security()._genKeys()
#t = Security()
#s = t.encrypt(b'test')
#print('encrypt', s)
#print('decrypt', t.decrypt(s))

app = App()
app._start()

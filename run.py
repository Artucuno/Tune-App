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
#import logging
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

import PySimpleGUI as sg
from pynput.keyboard import Key, Listener

def GraphicButton(text:str, key:str, image_data):
    text = text.replace('_', ' ')
    button = sg.Button('', image_data=image_data, button_color=('white', '#9FB8AD'), font='Any 15', key=key, border_width=0)
    text = sg.Text(text, font='Any 10', size=(15,1), justification='center',)
    return sg.Column([[button],[text]], element_justification='c')

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

class Keybinds:
    def __init__(self):
        self.pause_resume = None
        self.vol_up = None
        self.vol_down = None
        self.mute = None

    def init_keybinds(self):
        if os.path.isfile('keybinds.json'):
            try:
                with open('keybinds.json') as of:
                    data = json.load(of)
                    for p in data['Config']:
                        self.pause_resume = p['pause_resume']
                        self.vol_up = p['vol_up']
                        self.vol_down = p['vol_down']
                        self.mute = None
                        return
            except Exception as e:
                print('Unable to load keybinds')
        data = {}
        data['Config'] = []
        data['Config'].append({
        'pause_resume': 'Key.media_play_pause',
        'vol_up': 'Key.media_volume_up',
        'vol_down': 'Key.media_volume_down',
        'mute': None
        })
        with open('keybinds.json', 'w+') as of:
            json.dump(data, of)
        try:
            with open('keybinds.json') as of:
                data = json.load(of)
                for p in data['Config']:
                    self.pause_resume = p['pause_resume']
                    self.vol_up = p['vol_up']
                    self.vol_down = p['vol_down']
                    self.mute = None
                    return
        except Exception as e:
            print('Unable to load keybinds')
        return

    def set_keybind(self, name, key):
        pass

class App:
    def __init__(self):
        # Variables
        self.authors = [('Artucuno', 'https://artucuno.dev')]
        self.version = '1.1'
        self.API_ENDPOINT = 'https://tune.loona.gg/api/v1/'
        self.CLIENT_ID = '674866541346684938'
        self.auth = (False, None, 0)
        self.guild = 0

        # Presence Clients
        self.c = pypresence.Client(self.CLIENT_ID)
        self.rpc = pypresence.Presence(self.CLIENT_ID)

        self.security = Security()
        self.keybinds = Keybinds()
        self.keybinds.init_keybinds()

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
        if os.path.isfile('keybinds.json'):
            pass
        if self._checkForUpdate():
            print('The Tune App has an update! (It is recommended that you update.)\nhttps://github.com/Artucuno/Tune-App')
        if not os.path.isfile('logo.png'):
            try:
                self._downloadFile('https://tune.loona.gg/static/logo.png', 'logo.png')
            except:
                logger.warning('Unable to download Tune Logo')
        self.c.start()
        #self.c.register_event('ACTIVITY_JOIN', self.event_activity_join)
        #self.c.register_event('ACTIVITY_JOIN_REQUEST', self.event_activity_join_request)
        self.rpc.connect()

    def _checkForUpdate(self, timeout: int = 2):
        try:
            x = requests.get(self.API_ENDPOINT+'version', timeout=timeout)
            #print(x.text)
            #print(x.status_code)
            if str(x.text.strip()) == self.version:
                return False
            else:
                return True
        except Exception as e:
            #print(e)
            try:
                x = requests.get('https://raw.githubusercontent.com/Artucuno/Tune-App/main/version', timeout=timeout)
                if str(x.text.strip()) == self.version:
                    return False
                else:
                    return True
            except Exception as e:
                print(e)
                return None

    def _downloadFile(self, url: str, location: str):
        """Download a file using request streaming"""
        try:
            with requests.get(url, stream=True) as r:
                r.raise_for_status()
                with open(location, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
        except Exception as e:
            print(f'Unable to download {url}')
        return location

    def _toICO(self, filename: str, dir: str = None):
        """Convert an image to a .ICO"""
        img = Image.open(filename)
        if dir:
            img.save(os.path.join(dir, filename.split('/')[-1].split('.')[0]+'.ico'))
        else:
            img.save(filename.split('/')[-1].split('.')[0]+'.ico')
        return filename.split('.')[0]+'.ico'

    def event_activity_join(self, data):
        print('ACTIVITY_JOIN', data) # WIP

    def event_activity_join_request(self, data):
        print('ACTIVITY_JOIN_REQUEST', data) # WIP

    def on_press(self, key):
        #print('{0} pressed'.format(str(key)))
        if str(key) == self.keybinds.pause_resume:
            print('PLAY/PAUSE')
            try:
                Thread(target=lambda:requests.post(self.API_ENDPOINT+'bot/sendcommand', data={'code': open('auth', 'r').read(), 'guild': self.guild, 'command': 'play_pause'})).start()
            except:
                print('Unable to send command')
            time.sleep(2)
        elif str(key) == self.keybinds.vol_up:
            print('Volume up')
            try:
                Thread(target=lambda:requests.post(self.API_ENDPOINT+'bot/sendcommand', data={'code': open('auth', 'r').read(), 'guild': self.guild, 'command': 'vol_up'})).start()
            except:
                print('Unable to send command')
        elif str(key) == self.keybinds.vol_down:
            print('Volume down')
            try:
                Thread(target=lambda:requests.post(self.API_ENDPOINT+'bot/sendcommand', data={'code': open('auth', 'r').read(), 'guild': self.guild, 'command': 'vol_down'})).start()
            except:
                print('Unable to send command')

    def thread_getSong(self, gid):
        while True:
            try:
                x = requests.post(self.API_ENDPOINT+'getsong', data={'guild': gid})
                l = x.json()
                if 'error' not in l.keys():
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
                            print('Now playing: {} - {} ================='.format(p['trackdata']['author'], p['trackdata']['title']), end='\r')
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
            self._cf(f'data/user/{auth["user"]["id"]}')
            self._cf(f'data/user/{auth["user"]["id"]}/guilds')
            self._cf(f'data/user/{auth["user"]["id"]}/assets')
            self._cf(f'data/user/{auth["user"]["id"]}/assets/guilds')
            Notification(
            	title='Authenticated',
            	description='Welcome, {}!'.format(auth['user']['username']),
                icon_path=self._toICO(self._downloadFile(f'https://cdn.discordapp.com/avatars/{self.auth[2]}/{self.auth[1]["user"]["avatar"]}.jpg', f'data/user/{auth["user"]["id"]}/avatar.jpg'), f'data/user/{auth["user"]["id"]}'),
            	duration=5,
            	urgency='normal'
            ).send()
            gid = input('Enter your server id >> ')
            self.guild = gid
            Thread(target=lambda:self.thread_getSong(gid)).start()
            #while True:
            #    print(self.c.get_guilds())
                #try:
                #    print(self.c.get_guilds())
                #except:
                #    pass
        else: # Unauthenticated
            Notification(
            	title='Authenticated Failed',
            	description='Unable to authenticate (Make sure that you push Authorize!)',
            	duration=5,
            	urgency='normal'
            ).send()
            input('Thanks for using Tune!')
        #print(self.auth)
        x = requests.post(self.API_ENDPOINT+'user/getguilds', data={'code': open('auth', 'r').read()})
        for f in x.json()['guilds']:
            if not os.path.isfile(f'data/user/{auth["user"]["id"]}/assets/guilds/{f["icon"]}.jpg'):
                try:
                    Thread(target=lambda:self._downloadFile(f'https://cdn.discordapp.com/icons/{f["id"]}/{f["icon"]}.jpg', f'data/user/{auth["user"]["id"]}/assets/guilds/{f["id"]}.jpg')).start()
                except:
                    pass
            #print(f['id'], f['name'])
        print(len(x.json()['guilds']))
        with Listener(on_press=self.on_press) as listener:
            listener.join()

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

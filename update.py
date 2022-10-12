import sys, os
import shutil

try:
    shutil.rmtree('data')
except:
    pass

try:
    shutil.rmtree('build')
except:
    pass

try:
    shutil.rmtree('dist')
except:
    pass

for root, dirs, files in os.walk(".", topdown=False):
    for name in dirs:
        if name == '__pycache__':
            shutil.rmtree(os.path.join(root, name))

fo = ['avatar.ico', 'avatar.jpg', 'private_key.pem', 'public_key.pem', 'run.spec', 'auth', 'state', 'keybinds.json']
for f in fo:
    try:
        os.remove(f)
    except Exception as e:
        print(e)

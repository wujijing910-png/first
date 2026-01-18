from tkinter import messagebox,simpledialog, filedialog, Tk
from random import choice
from time import sleep
import os
from string import punctuation,ascii_letters,digits
from pathlib import Path
from base64 import b64encode, b64decode
import subprocess
from datetime import datetime
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except Exception:
    try:
        subprocess.run(['powershell','-Command','python -m pip install --upgrade pip'])
        subprocess.run(['powershell','-Command','python -m pip install cryptography'])
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        HAS_CRYPTO=True
    except BaseException:
        HAS_CRYPTO=False
class Encrypt:
    def get_task(self):
        task = simpledialog.askstring('Task', 'Do you want to encrypt or decrypt or encrypt text file or decrypt text file?')
        return task

    # 获取行为回答
    def get_task_file(self):
        script_dir = Path(__file__).resolve().parent
        # Show common text and encrypted/decrypted extensions so users can find .enc files
        filetypes = [
            ('Supported', ('*.txt', '*.enc', '*.dec')),
            ('Text files', '*.txt'),
            ('Encrypted files', '*.enc'),
            ('Decrypted files', '*.dec'),
            ('All files', '*.*'),
        ]
        filename = filedialog.askopenfilename(title='Select file', initialdir=str(script_dir), filetypes=filetypes)
        return filename

    # 获取内容回答
    def get_message(self):
        message = simpledialog.askstring('Message', 'Enter the secret message:')
        return message

    # 奇偶数判断
    def is_even(self, number):
        return number % 2 == 0

    # 提取偶数字母
    def get_even_letters(self, message):
        even_letters = []
        for count in range(len(message)):
            if self.is_even(count):
                even_letters.append(message[count])
        return even_letters

    # 提取无用字母
    def get_old_letters(self, message):
        old_letters = []
        for count in range(len(message)):
            if not self.is_even(count):
                old_letters.append(message[count])
        return old_letters

    # 交换字母
    def swap_letters(self, message):
        letter_list = []
        if not self.is_even(len(message)):
            message = message + 'x'
        even_letters = self.get_even_letters(message)
        old_letters = self.get_old_letters(message)

        for count in range(int(len(message) / 2)):
            letter_list.append(old_letters[count])
            letter_list.append(even_letters[count])
        new_message = ''.join(letter_list)
        return new_message

    # 加密（默认使用 AES，如果不可用或用户取消，则回退到原有简单算法）
    def encrypt(self, message, password: str = None):
        # Prefer AES-based encryption when cryptography is available
        if HAS_CRYPTO:
            pwd = password or os.environ.get('AES_PASSWORD') or os.environ.get('ENCRYPT_PASSWORD')
            if pwd is None:
                # Prompt user for a password via dialog (GUI apps)
                try:
                    root = Tk()
                    root.withdraw()
                    pwd = simpledialog.askstring('Password', 'Enter password to encrypt text:', show='*')
                    root.destroy()
                except Exception:
                    pwd = None
            if pwd:
                return self.aes_encrypt_text(message, pwd)
            # If user cancelled or no password provided, fall through to legacy method

        # Legacy (noise + swap) algorithm
        encrypted_list = []
        # 增加噪声字符：小写字母 + 数字 + 常见符号，使加密输出更复杂
        fake = list(ascii_letters+punctuation+digits)
        encrypted_list.append(choice(fake))
        encrypted_message = ''.join(encrypted_list)
        # 添加字母
        swapped_message = self.swap_letters(encrypted_message)
        # 交换字母
        encrypted_message = ''.join(reversed(swapped_message))
        # 倒置
        return encrypted_message

    # ---- AES helpers (use cryptography) ----
    def aes_encrypt_text(self, plaintext: str, password: str) -> str:
        if not HAS_CRYPTO:
            raise ImportError('cryptography library not available')
        salt = os.urandom(16)
        # derive key
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
        key = kdf.derive(password.encode('utf-8'))
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        blob = salt + nonce + ct
        return b64encode(blob).decode('ascii')

    def aes_decrypt_text(self, b64_blob: str, password: str) -> str:
        if not HAS_CRYPTO:
            raise ImportError('cryptography library not available')
        blob = b64decode(b64_blob)
        salt = blob[:16]
        nonce = blob[16:28]
        ct = blob[28:]
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
        key = kdf.derive(password.encode('utf-8'))
        aesgcm = AESGCM(key)
        try:
            pt = aesgcm.decrypt(nonce, ct, None)
        except Exception as e:
            raise e
        return pt.decode('utf-8')

    # 解密（默认使用 AES，如果不可用或用户取消则回退到原有简单算法）
    def decrypt(self, message, password: str = None):
        # Prefer AES-based decryption when cryptography is available
        if HAS_CRYPTO:
            pwd = password or os.environ.get('AES_PASSWORD') or os.environ.get('ENCRYPT_PASSWORD')
            if pwd is None:
                # Prompt user for a password via dialog (GUI apps)
                try:
                    root = Tk()
                    root.withdraw()
                    pwd = simpledialog.askstring('Password', 'Enter password to decrypt text:', show='*')
                    root.destroy()
                except Exception:
                    pwd = None
            if pwd:
                # aes_decrypt_text will raise if blob/password invalid
                return self.aes_decrypt_text(message, pwd)
            # If user cancelled or no password, fall back to legacy

        # Legacy (reverse of earlier noise method)
        unrversed_message = ''.join(reversed(message))
        # 倒置
        decrypted_message = self.swap_letters(unrversed_message)
        # 交换字母
        even_letters = self.get_even_letters(decrypted_message)
        # 提取字母
        new_message = ''.join(even_letters)
        return new_message

    # 文件路径解析（相对路径相对于脚本目录）
    def _resolve_path(self, m):
        script_dir = Path(__file__).resolve().parent
        p = Path(m)
        if not p.is_absolute():
            p = script_dir / m
        return p.resolve()

    # 文件加密
    def encrypt_file(self, m):
        path = self._resolve_path(m)
        if not path.exists():
            messagebox.showinfo('SORRY', f'Cannot find file: {path}\nScript dir: {Path(__file__).resolve().parent}\nCWD: {Path.cwd()}')
            raise FileNotFoundError(path)
        try:
            contents = path.read_text(encoding='utf-8').rstrip()
        except UnicodeDecodeError:
            contents = path.read_text(encoding='gbk').rstrip()
        # Ask for a password and use AES if available
        if not HAS_CRYPTO:
            messagebox.showinfo('Missing dependency', 'The cryptography package is not installed. Please install it with:\n\npip install cryptography')
            raise ImportError('cryptography not installed')
        pwd = simpledialog.askstring('Password', 'Enter password to encrypt file:', show='*')
        if pwd is None:
            raise FileNotFoundError('Encryption cancelled by user')
        encrypted_file = self.aes_encrypt_text(contents, pwd)
        # 保存为新文件：替换原后缀为 .enc（例如 test.txt -> test.enc）
        path_out = path.with_suffix('.enc')
        path_out.write_text(str(encrypted_file), encoding='utf-8')
        # 记录最新输出路径，便于测试或调用方查询
        self._last_output_path = path_out
        sleep(1)
        return encrypted_file

    # 文件解密
    def decrypt_file(self, m):
        path = self._resolve_path(m)
        if not path.exists():
            messagebox.showinfo('SORRY', f'Cannot find file: {path}\nScript dir: {Path(__file__).resolve().parent}\nCWD: {Path.cwd()}')
            raise FileNotFoundError(path)
        try:
            contents = path.read_text(encoding='utf-8').rstrip()
        except UnicodeDecodeError:
            contents = path.read_text(encoding='gbk').rstrip()
        # Ask for password and attempt AES decryption
        if not HAS_CRYPTO:
            messagebox.showinfo('Missing dependency', 'The cryptography package is not installed. Please install it with:\n\npip install cryptography')
            raise ImportError('cryptography not installed')
        pwd = simpledialog.askstring('Password', 'Enter password to decrypt file:', show='*')
        if pwd is None:
            raise FileNotFoundError('Decryption cancelled by user')
        try:
            decrypted_file = self.aes_decrypt_text(contents, pwd)
        except Exception:
            messagebox.showinfo('ERROR', 'Decryption failed — wrong password or corrupted file')
            raise
        # 保存为新文件：替换原后缀为 .dec（例如 secret.enc -> secret.dec）
        path_out = path.with_suffix('.dec')
        path_out.write_text(str(decrypted_file), encoding='utf-8')
        self._last_output_path = path_out
        sleep(1)
        return decrypted_file

    # 主循环（GUI）
    def start(self):
        root = Tk()
        root.withdraw()
        while True:
            task = self.get_task()
            # 加密
            if task == 'encrypt':
                message = self.get_message()
                encrypted = self.encrypt(message)
                messagebox.showinfo('Ciphertext of the secret message is:', encrypted)

            # 解密
            elif task == 'decrypt':
                message = self.get_message()
                decrypted = self.decrypt(message)
                messagebox.showinfo('Plaintext of secret message is:', decrypted)

            # 加密文件
            elif task in ('encryptfile', 'encrypt file', 'encrypt text file'):
                try:
                    message = self.get_task_file()
                    file_encrypted = self.encrypt_file(message)
                except FileNotFoundError:
                    messagebox.showinfo('SORRY', 'we cannot find this file,is you donot put the .txt and put it on this path?')
                    sleep(3)
                except UnicodeDecodeError:
                    messagebox.showinfo('ERROR', 'Please put gbk unicode file')
                else:
                    out = getattr(self, '_last_output_path', None)
                    if out:
                        try:
                            st = out.stat()
                            size = st.st_size
                            mtime = datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        except Exception:
                            size = 'unknown'
                            mtime = 'unknown'
                        prompt = f'Ciphertext saved to:\n{out}\nSize: {size} bytes\nModified: {mtime}\n\nOpen file location?'
                        if messagebox.askyesno('Saved', prompt):
                            try:
                                # Use explorer to open and select the file on Windows
                                subprocess.Popen(['explorer', f'/select,{str(out)}'])
                            except Exception:
                                try:
                                    os.startfile(out.parent)
                                except Exception:
                                    pass
                    else:
                        messagebox.showinfo('Ciphertext of the file is:', file_encrypted)

            elif task in ('decryptfile', 'decrypt file', 'decrypt text file'):
                try:
                    message = self.get_task_file()
                    file_decrypted = self.decrypt_file(message)
                except FileNotFoundError:
                    messagebox.showinfo('SORRY', 'we cannot find this file,is you donot put the .txt and put it on this path?')
                    sleep(3)
                except UnicodeDecodeError:
                    messagebox.showinfo('ERROR', 'Please put gbk unicode file')
                else:
                    out = getattr(self, '_last_output_path', None)
                    if out:
                        try:
                            st = out.stat()
                            size = st.st_size
                            mtime = datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        except Exception:
                            size = 'unknown'
                            mtime = 'unknown'
                        prompt = f'Plaintext saved to:\n{out}\nSize: {size} bytes\nModified: {mtime}\n\nOpen file location?'
                        if messagebox.askyesno('Saved', prompt):
                            try:
                                subprocess.Popen(['explorer', f'/select,{str(out)}'])
                            except Exception:
                                try:
                                    os.startfile(out.parent)
                                except Exception:
                                    pass
                    else:
                        messagebox.showinfo('Plaintext of the file is:', file_decrypted)
            else:
                root.destroy()
                quit()
            root.mainloop()
if __name__ == '__main__':
    app = Encrypt()
    app.start()
import tkinter as tk 
from tkinter import filedialog, messagebox 
import os 
import pickle 
from Crypto.Cipher import AES 
from Crypto.Protocol.KDF import PBKDF2 
from Crypto.Random import get_random_bytes
import hashlib 


os.makedirs("encrypted_files", exist_ok=True)


USERS_FILE = "users.pkl"
if os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'rb') as f:
        users = pickle.load(f)
else:
    users = {}


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def derive_key(password):
    salt = b'static_salt'  
    return PBKDF2(password, salt, dkLen=32)


def encrypt_file(file_path, key, username):
    user_dir = os.path.join("encrypted_files", username)
    os.makedirs(user_dir, exist_ok=True) 
    
    cipher = AES.new(key, AES.MODE_EAX)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    file_name = os.path.basename(file_path)
    with open(os.path.join(user_dir, f'{file_name}.enc'), 'wb') as f:
        f.write(cipher.nonce)
        f.write(tag)
        f.write(ciphertext)
    return f'{file_name}.enc'


def decrypt_file(file_name, key, username):
    path = os.path.join("encrypted_files", username, file_name)
    with open(path, 'rb') as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    original_name = file_name.replace(".enc", "")
    save_path = filedialog.asksaveasfilename(initialfile=original_name)

    if save_path:
        with open(save_path, 'wb') as f:
            f.write(plaintext)
        messagebox.showinfo("Success", f"File decrypted and saved to:\n{save_path}")


class SecureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Storage")
        self.username = None
        self.key = None
        self.build_login()
        
    
    def build_login(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text="Username").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()
        tk.Label(self.root, text="Password").pack()
        self.password_entry = tk.Entry(self.root, show='*')
        self.password_entry.pack()

        tk.Button(self.root, text="Login", command=self.login).pack(pady=5)
        tk.Button(self.root, text="Register", command=self.register).pack()
    
    
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        hashed = hash_password(password)

        if username in users and users[username] == hashed:
            self.username = username
            self.key = derive_key(password)
            self.build_main()
        else:
            messagebox.showerror("Error", "Invalid credentials")

    
    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username in users:
            messagebox.showerror("Error", "User already exists")
        else:
            users[username] = hash_password(password)
            with open(USERS_FILE, 'wb') as f:
                pickle.dump(users, f)
            messagebox.showinfo("Success", "Registered successfully!")

    
    def build_main(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text=f"Welcome, {self.username}!", font=('Arial', 14)).pack(pady=10)

        tk.Button(self.root, text="Upload File", command=self.upload_file).pack(pady=5)
        tk.Label(self.root, text="Encrypted Files:").pack()

        self.file_listbox = tk.Listbox(self.root)
        self.file_listbox.pack(pady=5)
        self.refresh_files()

        tk.Button(self.root, text="Decrypt & Save Selected File", command=self.decrypt_selected).pack(pady=5)
        tk.Button(self.root, text="Logout", command=self.build_login).pack(pady=10)

    
    def refresh_files(self):
        self.file_listbox.delete(0, tk.END)
        user_dir = os.path.join("encrypted_files", self.username)
        if os.path.exists(user_dir):
            files = os.listdir(user_dir)
            for f in files:
                self.file_listbox.insert(tk.END, f)


    
    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            enc_file = encrypt_file(file_path, self.key, self.username)
            messagebox.showinfo("Success", f"File encrypted as: {enc_file}")
            self.refresh_files()


    
    def decrypt_selected(self):
        selection = self.file_listbox.curselection()
        if selection:
            file_name = self.file_listbox.get(selection[0])
            try:
                decrypt_file(file_name, self.key, self.username)
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed:\n{e}")
        else:
            messagebox.showwarning("Warning", "No file selected")


root = tk.Tk()
root.geometry("400x450")
app = SecureApp(root)
root.mainloop()

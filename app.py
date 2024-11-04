import tkinter as tk
from tkinter import messagebox, filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

class HealthcareApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Patient Record System")
        self.master.geometry("800x600")
        self.master.configure(bg='lightblue')

        # Initialize RSA keys (Load from file or generate fresh ones)
        self.private_key, self.public_key = self.load_rsa_keys()

        self.patients = {}
        self.doctors = {}
        self.patient_details = {}  # Stores encrypted sickness data
        self.patient_status = {}

        self.login_frame = tk.Frame(master, bg='lightblue')
        self.login_frame.pack(pady=20)

        # Login UI
        self.username_label = tk.Label(self.login_frame, text="Username", font=("Helvetica", 16), bg='lightblue')
        self.username_label.grid(row=0, column=0)
        self.username_entry = tk.Entry(self.login_frame, font=("Helvetica", 16))
        self.username_entry.grid(row=0, column=1)

        self.password_label = tk.Label(self.login_frame, text="Password", font=("Helvetica", 16), bg='lightblue')
        self.password_label.grid(row=1, column=0)
        self.password_entry = tk.Entry(self.login_frame, show="*", font=("Helvetica", 16))
        self.password_entry.grid(row=1, column=1)

        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login, font=("Helvetica", 16))
        self.login_button.grid(row=2, columnspan=2)

        # Registration UI
        self.register_frame = tk.Frame(master, bg='lightblue')
        self.register_frame.pack(pady=20)

        self.role_label = tk.Label(self.register_frame, text="Role (Patient/Doctor)", font=("Helvetica", 16), bg='lightblue')
        self.role_label.grid(row=0, column=0)
        self.role_entry = tk.Entry(self.register_frame, font=("Helvetica", 16))
        self.role_entry.grid(row=0, column=1)

        self.reg_username_label = tk.Label(self.register_frame, text="Username", font=("Helvetica", 16), bg='lightblue')
        self.reg_username_label.grid(row=1, column=0)
        self.reg_username_entry = tk.Entry(self.register_frame, font=("Helvetica", 16))
        self.reg_username_entry.grid(row=1, column=1)

        self.reg_password_label = tk.Label(self.register_frame, text="Password", font=("Helvetica", 16), bg='lightblue')
        self.reg_password_label.grid(row=2, column=0)
        self.reg_password_entry = tk.Entry(self.register_frame, show="*", font=("Helvetica", 16))
        self.reg_password_entry.grid(row=2, column=1)

        self.register_button = tk.Button(self.register_frame, text="Register", command=self.register, font=("Helvetica", 16))
        self.register_button.grid(row=3, columnspan=2)

        self.dashboard_frame = None

    # Load RSA keys from files
    def load_rsa_keys(self):
        try:
            with open('private.pem', 'rb') as f:
                private_key = RSA.import_key(f.read())
            with open('public.pem', 'rb') as f:
                public_key = RSA.import_key(f.read())
        except FileNotFoundError:
            # Generate new RSA keys if not found
            private_key, public_key = self.generate_rsa_keys()
        return private_key, public_key

    # Generate RSA keys
    def generate_rsa_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Save the keys to files
        with open('private.pem', 'wb') as f:
            f.write(private_key)
        with open('public.pem', 'wb') as f:
            f.write(public_key)

        return RSA.import_key(private_key), RSA.import_key(public_key)

    # AES Encryption
    def encrypt_data(self, data):
        aes_key = get_random_bytes(16)  # 128-bit AES key
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode('utf-8'))

        # Encrypt the AES key with RSA
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Return both encrypted AES key and encrypted data
        return base64.b64encode(encrypted_aes_key), base64.b64encode(cipher_aes.nonce + tag + ciphertext)

    # AES Decryption
    def decrypt_data(self, encrypted_aes_key, encrypted_data):
        encrypted_aes_key = base64.b64decode(encrypted_aes_key)
        encrypted_data = base64.b64decode(encrypted_data)

        # Decrypt AES key using RSA
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        # Decrypt the data with AES
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        return data.decode('utf-8')

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username in self.patients and self.patients[username] == password:
            self.show_patient_dashboard(username)
        elif username in self.doctors and self.doctors[username] == password:
            self.show_doctor_dashboard()
        else:
            messagebox.showerror("Error", "Invalid credentials")

    def register(self):
        role = self.role_entry.get().lower()
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()

        if role == "patient":
            self.patients[username] = password
            self.patient_details[username] = ""
            self.patient_status[username] = "Normal"  # Default status
            messagebox.showinfo("Success", "Patient registered successfully")
        elif role == "doctor":
            self.doctors[username] = password
            messagebox.showinfo("Success", "Doctor registered successfully")
        else:
            messagebox.showerror("Error", "Invalid role")

    def show_patient_dashboard(self, username):
        if self.dashboard_frame:
            self.dashboard_frame.destroy()

        self.dashboard_frame = tk.Frame(self.master, bg='lightblue')
        self.dashboard_frame.pack(pady=20)

        tk.Label(self.dashboard_frame, text="Patient Dashboard", font=("Helvetica", 24), bg='lightblue').pack()

        self.sickness_entry = tk.Entry(self.dashboard_frame, font=("Helvetica", 16))
        self.sickness_entry.pack(pady=10)
        self.sickness_entry.insert(0, "Describe your sickness...")

        tk.Button(self.dashboard_frame, text="Upload File", command=self.upload_file, font=("Helvetica", 16)).pack(pady=10)
        tk.Button(self.dashboard_frame, text="Submit", command=lambda: self.submit_sickness(username), font=("Helvetica", 16)).pack(pady=10)

        self.status_label = tk.Label(self.dashboard_frame, text=f"Health Status: {self.patient_status[username]}", 
                                      font=("Helvetica", 16), bg='lightblue')
        self.status_label.pack(pady=10)
        self.update_status_color(username)

    def submit_sickness(self, username):
        sickness = self.sickness_entry.get()

        # Encrypt sickness details
        encrypted_aes_key, encrypted_sickness = self.encrypt_data(sickness)
        self.patient_details[username] = (encrypted_aes_key, encrypted_sickness)

        messagebox.showinfo("Sickness Submitted", "Sickness details have been encrypted and submitted.")

        # Set status based on sickness description
        if "critical" in sickness.lower():
            self.patient_status[username] = "Critical"
        else:
            self.patient_status[username] = "Normal"

        self.update_status_color(username)

    def update_status_color(self, username):
        status = self.patient_status[username]
        if status == "Critical":
            self.status_label.config(fg='red')
        else:
            self.status_label.config(fg='green')

    def view_patient_records(self):
        records = ""
        for username in self.patients:
            encrypted_aes_key, encrypted_sickness = self.patient_details[username]
            # Decrypt sickness details
            sickness = self.decrypt_data(encrypted_aes_key, encrypted_sickness)
            records += f"Patient: {username}, Status: {self.patient_status[username]}, Sickness: {sickness}\n"
        
        if records:
            messagebox.showinfo("Patient Records", records)
        else:
            messagebox.showinfo("Patient Records", "No patient records found.")

    def update_patient_status(self):
        patient_username = self.patient_username_entry.get()
        new_status = self.status_entry.get()

        if patient_username in self.patient_status and new_status in ["Normal", "Critical"]:
            self.patient_status[patient_username] = new_status
            messagebox.showinfo("Success", f"Updated status for {patient_username} to {new_status}")
            self.view_patient_records()

    def show_doctor_dashboard(self):
        if self.dashboard_frame:
            self.dashboard_frame.destroy()

        self.dashboard_frame = tk.Frame(self.master, bg='lightblue')
        self.dashboard_frame.pack(pady=20)

        tk.Label(self.dashboard_frame, text="Doctor Dashboard", font=("Helvetica", 24), bg='lightblue').pack()

        tk.Button(self.dashboard_frame, text="View Patient Records", command=self.view_patient_records, font=("Helvetica", 16)).pack(pady=10)

        self.patient_username_entry = tk.Entry(self.dashboard_frame, font=("Helvetica", 16))
        self.patient_username_entry.pack(pady=10)
        self.patient_username_entry.insert(0, "Enter patient username")

        self.status_entry = tk.Entry(self.dashboard_frame, font=("Helvetica", 16))
        self.status_entry.pack(pady=10)
        self.status_entry.insert(0, "Enter new status (Normal/Critical)")

        tk.Button(self.dashboard_frame, text="Update Patient Status", command=self.update_patient_status, font=("Helvetica", 16)).pack(pady=10)

    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            messagebox.showinfo("File Uploaded", f"File uploaded successfully: {file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = HealthcareApp(root)
    root.mainloop()

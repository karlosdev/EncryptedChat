import socket
import threading
import customtkinter as ctk
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import hashlib

# ustawienie wyglądu ctk
ctk.set_appearance_mode("dark")  # tryb ciemny
ctk.set_default_color_theme("blue")  # motyw niebieski


# generowanie pary kluczy RSA
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


# szyfrowanie wiadomości używając AES i RSA
def encrypt_message(message, session_key, public_key):
    # szyfrowanie AES
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))

    # szyfrowanie klucza sesji za pomocą RSA
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    # zwraca zaszyfrowaną wiadomość, nonce AES i hash SHA256
    return encrypted_session_key + cipher_aes.nonce + tag + ciphertext, cipher_aes.nonce.hex(), hashlib.sha256(
        message.encode()).hexdigest()


# deszyfrowanie wiadomości używając AES i RSA
def decrypt_message(encrypted_message, private_key):
    # rozdzielenie komponentów zaszyfrowanej wiadomości
    encrypted_session_key = encrypted_message[:256]
    nonce = encrypted_message[256:272]
    tag = encrypted_message[272:288]
    ciphertext = encrypted_message[288:]

    # deszyfrowanie klucza sesji za pomocą RSA
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    session_key = cipher_rsa.decrypt(encrypted_session_key)

    # deszyfrowanie wiadomości za pomocą AES
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return message.decode('utf-8'), nonce.hex(), hashlib.sha256(message).hexdigest()


class HostGUI:
    def __init__(self, master):
        self.master = master
        master.title("Host")
        master.geometry("600x400")

        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(0, weight=1)

        # ramka główna
        main_frame = ctk.CTkFrame(master)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)

        # obszar wyświetlania czatu
        self.chat_display = ctk.CTkTextbox(main_frame, state='disabled', wrap='word')
        self.chat_display.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

        # pole wprowadzania wiadomości
        self.msg_entry = ctk.CTkEntry(main_frame, placeholder_text="Wpisz wiadomość...")
        self.msg_entry.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

        # przycisk wysyłania
        self.send_button = ctk.CTkButton(main_frame, text="Wyślij", command=self.send_message)
        self.send_button.grid(row=1, column=1, sticky="e", padx=5, pady=5)

        # generowanie kluczy RSA
        self.private_key, self.public_key = generate_keys()
        self.client_public_key = None
        self.client_socket = None

        # uruchomienie serwera w osobnym wątku
        threading.Thread(target=self.start_server, daemon=True).start()

    def start_server(self):
        # inicjalizacja i uruchomienie serwera
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', 5000))
        server.listen(1)
        self.update_chat("Serwer nasłuchuje na porcie 5000...")

        self.client_socket, addr = server.accept()
        self.update_chat(f"Połączenie przychodzące od {addr}")

        # wymiana kluczy publicznych
        self.client_public_key = self.client_socket.recv(1024)
        self.client_socket.send(self.public_key)

        # uruchomienie odbierania wiadomości w osobnym wątku
        threading.Thread(target=self.receive_messages, daemon=True).start()

    # odbieranie i deszyfrowanie wiadomości od klienta
    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(4096)
                if not encrypted_message:
                    break
                message, aes_nonce, sha256_hash = decrypt_message(encrypted_message, self.private_key)
                #self.update_chat(f"Klient: {message}\nAES Nonce: {aes_nonce}\nSHA256: {sha256_hash}")
                self.update_chat(f"Klient: {message}")
            except:
                break
        self.client_socket.close()

    # szyfrowanie i wysyłanie wiadomości do klienta
    def send_message(self):
        message = self.msg_entry.get()
        if message and self.client_socket and self.client_public_key:
            session_key = get_random_bytes(16)
            encrypted_message, aes_nonce, sha256_hash = encrypt_message(message, session_key, self.client_public_key)
            self.client_socket.send(encrypted_message)
            #self.update_chat(f"Ty: {message}\nAES Nonce: {aes_nonce}\nSHA256: {sha256_hash}")
            self.update_chat(f"Ty: {message}")
            self.msg_entry.delete(0, ctk.END)

    # aktualizowanie obszaru wyświetlania czatu
    def update_chat(self, message):
        self.chat_display.configure(state='normal')
        self.chat_display.insert(ctk.END, message + '\n\n')
        self.chat_display.configure(state='disabled')
        self.chat_display.see(ctk.END)


root = ctk.CTk()
host_gui = HostGUI(root)
root.mainloop()

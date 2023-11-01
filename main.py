import tkinter as tk
from tkinter import *
from tkinter import messagebox,ttk

class CryptoApp:
    def __init__(self):
        self.username = "aymen"
        self.password = "hello"

        # Create the authentication window
        self.authentication_frame = tk.Tk()
        self.authentication_frame.geometry("375x200")
        self.authentication_frame.title("Authentication")
        #icon
        image_icon=PhotoImage(file="keys.png")
        self.authentication_frame.iconphoto(False,image_icon)

        username_label = Label(self.authentication_frame, text="Username:",fg="black",font=("calbri",13))
        self.username_field = ttk.Entry(self.authentication_frame, width=25)
        password_label = Label(self.authentication_frame, text="Password:",fg="black",font=("calbri",13))
        self.password_field = Entry(self.authentication_frame, show="*", width=25)
        login_button = Button(self.authentication_frame, height="2",width=50,bg="#1089ff",fg="white",bd=0,text="Login", command=self.authenticate)

        username_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.username_field.grid(row=2, column=1, padx=5, pady=5)
        password_label.grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.password_field.grid(row=4, column=1, padx=5, pady=5)
        login_button.grid(row=6, column=0, columnspan=2, padx=5, pady=10, sticky="e")

    def authenticate(self):
        entered_username = self.username_field.get()
        entered_password = self.password_field.get()

        if entered_username == self.username and entered_password == self.password:
            self.authentication_frame.destroy()
            self.initialize_app()
        else:
            messagebox.showerror("Authentication Failed", "Authentication failed. Please check your username and password.")

    def initialize_app(self):
        main_frame = tk.Tk()
        main_frame.title("Message Encrypter/Decrypter")

        # Configure the main window layout
        main_frame.geometry("500x400")
        main_frame.configure(bg="#f0f0f0")  # Set background color

        self.input_text = Text(main_frame, height=5, width=30,fg="black",font=("calbri",13))
        self.output_text = Text(main_frame, height=5, width=30,fg="black",font=("calbri",13))
        self.key_field = Entry(main_frame, width=20,fg="black",font=("calbri",13))

        # Create a frame for the buttons
        button_frame = ttk.Frame(main_frame)
        encrypt_button = Button(button_frame, text="Encrypt", height="2",width=23,bg="#ed3833",fg="white",bd=0,command=self.encrypt)
        decrypt_button = Button(button_frame, text="Decrypt",height="2",width=23,bg="#00bd56",fg="white",bd=0, command=self.decrypt)

        input_label = Label(main_frame, text="Message:",fg="black",font=("calbri",13))
        key_label = Label(main_frame, text="Key:",fg="black",font=("calbri",13))
        result_label = Label(main_frame, text="Result:",fg="black",font=("calbri",13))

        # Apply grid layout for widgets
        input_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.input_text.grid(row=0, column=1, padx=10, pady=10)
        key_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.key_field.grid(row=1, column=1, padx=10, pady=10)
        button_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=10)
        encrypt_button.grid(row=0, column=0, padx=10)
        decrypt_button.grid(row=0, column=1, padx=10)
        result_label.grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.output_text.grid(row=3, column=1, padx=10, pady=10)

        # Add some padding around widgets for better spacing
        for widget in (input_label, key_label, result_label):
            widget.grid_configure(padx=5, pady=5)

    def encrypt(self):
        message = self.input_text.get("1.0", "end-1c")
        key = self.key_field.get()
        encrypted_message = self.encrypt_text(message, key)
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", encrypted_message)

    def decrypt(self):
        message = self.input_text.get("1.0", "end-1c")
        key = self.key_field.get()
        decrypted_message = self.decrypt_text(message, key)
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", decrypted_message)

    @staticmethod
    def encrypt_text(message, key):
        result = []
        key_length = len(key)
        for i, char in enumerate(message):
            key_char = key[i % key_length]
            encrypted_char = chr(ord(char) ^ ord(key_char))
            result.append(encrypted_char)
        return ''.join(result)

    def decrypt_text(self, message, key):
        return self.encrypt_text(message, key)

if __name__ == "__main__":
    app = CryptoApp()
    tk.mainloop()

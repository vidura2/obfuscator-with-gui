import os
import tkinter as tk
from tkinter import filedialog, messagebox

# Key for XOR encryption (you can customize this key)
xor_encryption_key = 0x42

# Key for Caesar cipher encryption (you can customize this key)
caesar_cipher_key = 3

def obfuscate_executable():
    input_exe_file = input_file_entry.get()
    try:
        # Get the directory of the input .exe file
        input_dir = os.path.dirname(input_exe_file)

        # Determine the output .exe file path in the same directory
        input_filename = os.path.basename(input_exe_file)
        output_exe_path = os.path.join(input_dir, "obfuscated_" + input_filename)

        # Read the binary data from the input .exe file
        with open(input_exe_file, 'rb') as input_file:
            binary_data = input_file.read()
        
        # XOR encrypt the binary data
        xor_encrypted_data = bytes([byte ^ xor_encryption_key for byte in binary_data])
        
        # Caesar cipher encrypt the XOR encrypted data
        caesar_encrypted_data = bytes([(byte + caesar_cipher_key) % 256 for byte in xor_encrypted_data])
        
        # Write the obfuscated data to the output .exe file
        with open(output_exe_path, 'wb') as output_file:
            output_file.write(caesar_encrypted_data)
        
        messagebox.showinfo("Obfuscation Complete", "Obfuscated executable saved to:\n" + output_exe_path)
    except Exception as e:
        messagebox.showerror("Error", "Error obfuscating the executable:\n" + str(e))

def browse_input_file():
    input_file_path = filedialog.askopenfilename(filetypes=[("Executable Files", "*.exe")])
    input_file_entry.delete(0, tk.END)
    input_file_entry.insert(0, input_file_path)

def browse_output_file():
    output_file_path = filedialog.asksaveasfilename(defaultextension=".exe")
    output_file_entry.delete(0, tk.END)
    output_file_entry.insert(0, output_file_path)

# Create a GUI window
root = tk.Tk()
root.title("Executable Obfuscation")

# Create and configure GUI components
frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

matrix_label = tk.Label(frame, text="Welcome to Matrix", font=("Courier", 16))
matrix_label.pack()

input_file_label = tk.Label(frame, text="Select the input .exe file:")
input_file_label.pack()

input_file_entry = tk.Entry(frame, width=50)
input_file_entry.pack()

browse_input_button = tk.Button(frame, text="Browse", command=browse_input_file)
browse_input_button.pack()

obfuscate_button = tk.Button(frame, text="Obfuscate", command=obfuscate_executable)
obfuscate_button.pack()

output_file_label = tk.Label(frame, text="Save obfuscated file as:")
output_file_label.pack()

output_file_entry = tk.Entry(frame, width=50)
output_file_entry.pack()

browse_output_button = tk.Button(frame, text="Browse", command=browse_output_file)
browse_output_button.pack()

# Start the GUI
root.mainloop()

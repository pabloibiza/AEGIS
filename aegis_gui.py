#!/usr/bin/env python3
"""
AEGIS GUI - Graphical Interface for Windows
Triple Layer Encryption System
RSA-4096 + Double Layer AES (AES-256-GCM + AES-256-EAX)
"""

import os
import sys
import platform
# Try to import tkinter
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    print("\nERROR: tkinter is not installed\n")
    print("Tkinter is required for the graphical interface.")
    print("\nInstallation instructions:")
    print("  • Debian/Ubuntu:  sudo apt-get install python3-tk")
    print("  • Fedora/RHEL:    sudo dnf install python3-tkinter")
    print("  • Arch Linux:     sudo pacman -S tk")
    print("  • macOS:          brew install python-tk")
    print("  • Windows:        Included with Python installer\n")
    print("Or use the command-line version: python aegis.py --help\n")
    sys.exit(1)

import threading
from pathlib import Path
from typing import Callable, Optional

# Configure path to import main module
_script_dir = os.path.dirname(os.path.abspath(__file__))
_system = platform.system().lower()

# Select lib folder based on OS
if _system == 'windows':
    _lib_path = os.path.join(_script_dir, 'lib')
elif _system == 'linux':
    _lib_path = os.path.join(_script_dir, 'lib_linux')
elif _system == 'darwin':  # macOS
    _lib_path = os.path.join(_script_dir, 'lib_macos')
else:
    _lib_path = None

# Add lib folder to path
if _lib_path and os.path.exists(_lib_path) and _lib_path not in sys.path:
    sys.path.insert(0, _lib_path)

# Import functions from main module
try:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256
except (ImportError, OSError) as e:
    # Try automatic installation
    import subprocess
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "pycryptodome"])
        messagebox.showinfo("Installation", "PyCryptodome installed. Please restart the application.")
        sys.exit(0)
    except:
        messagebox.showerror("Error", "Could not install PyCryptodome.\nPlease run: pip install pycryptodome")
        sys.exit(1)

# Import functions from aegis.py
import aegis

# Colors for modern theme
COLORS = {
    'bg': '#1e1e1e',
    'fg': '#ffffff',
    'accent': '#007acc',
    'accent_hover': '#005a9e',
    'success': '#4ec9b0',
    'error': '#f48771',
    'warning': '#dcdcaa',
    'card': '#252526',
    'border': '#3e3e42',
}
AEGIS_ICON = 'aegis.png'

class VerboseRedirector:
    """Redirects stdout/stderr to the verbose text widget"""
    def __init__(self, text_widget, original_stream, is_error=False):
        self.text_widget = text_widget
        self.original_stream = original_stream
        self.is_error = is_error
    
    def write(self, text):
        """Write text to both the original stream and the text widget"""
        # Write to original stream
        if self.original_stream:
            self.original_stream.write(text)
            self.original_stream.flush()
        
        # Write to text widget if it exists
        if self.text_widget and self.text_widget.winfo_exists():
            self.text_widget.config(state='normal')
            
            # Detect type of message and apply color
            tag = None
            if '[ERROR]' in text or 'ERROR' in text or 'Error' in text:
                tag = 'error'
            elif '[OK]' in text or 'OK]' in text or 'success' in text.lower():
                tag = 'success'
            elif '[*]' in text or 'STEP' in text:
                tag = 'info'
            elif '[!]' in text or 'IMPORTANT' in text or 'Warning' in text:
                tag = 'warning'
            elif self.is_error:
                tag = 'error'
            
            if tag:
                self.text_widget.insert('end', text, tag)
            else:
                self.text_widget.insert('end', text)
            
            self.text_widget.see('end')
            self.text_widget.config(state='disabled')
    
    def flush(self):
        """Flush the stream"""
        if self.original_stream:
            self.original_stream.flush()


class AegisGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AEGIS - Triple Layer Encryption")
        self.root.geometry("600x420")
        self.root.minsize(550, 400)
        
        # Variables
        self.current_operation = None
        self.is_processing = False
        self.cancel_requested = False
        self.verbose_mode = False
        self.verbose_window = None
        self.verbose_text = None
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        
        # Load AEGIS icon
        self.aegis_icon = None
        self.load_icon()
        
        # Configurar estilo
        self.setup_style()
        
        # Crear interfaz
        self.create_widgets()
        
        # Centrar ventana
        self.center_window()
    
    def load_icon(self):
        """Load the AEGIS icon from aegis.png"""
        try:
            icon_path = os.path.join(_script_dir, AEGIS_ICON)
            if os.path.exists(icon_path):
                try:
                    # Try to use PIL for better quality
                    from PIL import Image, ImageTk
                    img = Image.open(icon_path)
                    # Resize to appropriate size (24x24 pixels for header)
                    img = img.resize((24, 24), Image.Resampling.LANCZOS)
                    self.aegis_icon = ImageTk.PhotoImage(img)
                except ImportError:
                    # Fallback to tkinter's PhotoImage
                    self.aegis_icon = tk.PhotoImage(file=icon_path)
                    # Subsample to reduce size (if needed)
                    self.aegis_icon = self.aegis_icon.subsample(
                        max(1, self.aegis_icon.width() // 24),
                        max(1, self.aegis_icon.height() // 24)
                    )
        except Exception as e:
            print(f"Warning: Could not load aegis.png icon: {e}")
            self.aegis_icon = None
    
    def setup_style(self):
        """Configure the visual style of the application"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure general colors
        self.root.configure(bg=COLORS['bg'])
        
        # Style for frames
        style.configure('Card.TFrame', background=COLORS['card'], borderwidth=1, relief='solid')
        style.configure('Main.TFrame', background=COLORS['bg'])
        
        # Style for labels
        style.configure('Title.TLabel', background=COLORS['bg'], foreground='#f0f0f0', 
                       font=('Segoe UI', 11, 'bold'))
        style.configure('Subtitle.TLabel', background=COLORS['card'], foreground=COLORS['fg'], 
                       font=('Segoe UI', 10))
        style.configure('Info.TLabel', background=COLORS['card'], foreground=COLORS['fg'], 
                       font=('Segoe UI', 8), relief='flat', borderwidth=0)
        style.configure('Status.TLabel', background=COLORS['bg'], foreground=COLORS['fg'], 
                       font=('Segoe UI', 9))
        
        # Style for notebook (tabs)
        style.configure('TNotebook', background=COLORS['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', background=COLORS['card'], foreground=COLORS['fg'], 
                       padding=[15, 8], font=('Segoe UI', 9))
        style.map('TNotebook.Tab', background=[('selected', COLORS['accent'])], 
                 foreground=[('selected', COLORS['fg'])])
        
        # Style for progressbar
        style.configure('TProgressbar', background=COLORS['accent'], troughcolor=COLORS['card'], 
                       borderwidth=0, thickness=12)
    
    def create_widgets(self):
        """Create all interface widgets"""
        # Header
        header_frame = ttk.Frame(self.root, style='Main.TFrame')
        header_frame.pack(fill='x', padx=8, pady=(8, 3))
        
        # Title with icon or emoji fallback
        if self.aegis_icon:
            title_label = tk.Label(header_frame, text=" AEGIS - Triple Layer Encryption",
                                  image=self.aegis_icon, compound='left',
                                  bg=COLORS['bg'], fg='#f0f0f0',
                                  font=('Segoe UI', 11, 'bold'))
        else:
            title_label = ttk.Label(header_frame, text="🛡️ AEGIS - Triple Layer Encryption", style='Title.TLabel')
        title_label.pack(side='left', anchor='w')
        
        # Verbose mode button
        self.verbose_button = tk.Button(header_frame, text="📋 Verbose", 
                                       bg=COLORS['accent'], fg=COLORS['fg'],
                                       font=('Segoe UI', 8, 'bold'),
                                       relief='flat', cursor='hand2',
                                       padx=10, pady=5,
                                       command=self.toggle_verbose_window)
        self.verbose_button.pack(side='right', padx=5)
        
        # Notebook (Tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=8, pady=3)
        
        # Tab 1: Encrypt
        self.encrypt_tab = ttk.Frame(self.notebook, style='Main.TFrame')
        self.notebook.add(self.encrypt_tab, text='🔒 Encrypt File')
        self.create_encrypt_tab()
        
        # Tab 2: Decrypt
        self.decrypt_tab = ttk.Frame(self.notebook, style='Main.TFrame')
        self.notebook.add(self.decrypt_tab, text='🔓 Decrypt File')
        self.create_decrypt_tab()
        
        # Status bar
        self.status_frame = ttk.Frame(self.root, style='Main.TFrame')
        self.status_frame.pack(fill='x', padx=8, pady=(0, 8))
        
        self.status_label = ttk.Label(self.status_frame, text="Ready", style='Status.TLabel')
        self.status_label.pack(side='left', fill='x', expand=True)
        
        # Cancel button (hidden initially)
        self.cancel_button = tk.Button(self.status_frame, text="✕ Cancel", 
                                      bg=COLORS['error'], fg=COLORS['fg'],
                                      font=('Segoe UI', 8, 'bold'),
                                      relief='flat', cursor='hand2',
                                      padx=10, pady=5,
                                      command=self.cancel_operation)
        # Hidden initially
        
        # Progress bar (always visible, full width)
        progress_container = ttk.Frame(self.root, style='Main.TFrame')
        progress_container.pack(fill='x', padx=8, pady=(0, 8))
        
        self.progress_bar = ttk.Progressbar(progress_container, mode='determinate', length=300)
        self.progress_bar.pack(fill='x', expand=True)
        self.progress_bar['value'] = 0
    
    def create_encrypt_tab(self):
        """Create the encryption tab"""
        # Main card
        card = ttk.Frame(self.encrypt_tab, style='Card.TFrame')
        card.pack(fill='both', expand=True, padx=8, pady=8)
        
        # Title
        title = ttk.Label(card, text="Encrypt File", style='Subtitle.TLabel')
        title.pack(anchor='w', padx=10, pady=(8, 4))
        
        # Drop zone
        self.encrypt_drop_frame = tk.Frame(card, bg=COLORS['border'], height=80)
        self.encrypt_drop_frame.pack(fill='x', padx=10, pady=4)
        self.encrypt_drop_frame.pack_propagate(False)
        
        drop_label = tk.Label(self.encrypt_drop_frame, 
                             text="📁 Drag file or click",
                             bg=COLORS['card'], fg=COLORS['fg'], 
                             font=('Segoe UI', 9), cursor='hand2')
        drop_label.pack(expand=True, fill='both', padx=2, pady=2)
        drop_label.bind('<Button-1>', lambda e: self.select_encrypt_file())
        
        # Configure drag and drop
        try:
            self.encrypt_drop_frame.drop_target_register(DND_FILES)
            self.encrypt_drop_frame.dnd_bind('<<Drop>>', self.on_encrypt_drop)
        except:
            pass  # If tkinterdnd2 is not available
        
        # Selected file with clear button
        file_frame = ttk.Frame(card, style='Main.TFrame', height=20)
        file_frame.pack(fill='x', padx=10, pady=2)
        file_frame.pack_propagate(False)
        
        self.encrypt_file_label = ttk.Label(file_frame, text="No file selected", 
                                           style='Info.TLabel')
        self.encrypt_file_label.pack(side='left')
        
        self.encrypt_clear_button = tk.Button(file_frame, text="✕", 
                                             bg=COLORS['error'], fg=COLORS['fg'],
                                             font=('Segoe UI', 7),
                                             relief='flat', cursor='hand2',
                                             padx=2, pady=0,
                                             command=self.clear_encrypt_file)
        # Button hidden initially
        self.encrypt_clear_button.pack_forget()
        
        # Information
        info_text = ("ℹ️ Generates: .enc (encrypted), .keys (symmetric), .rsakey (private key)")
        info_label = ttk.Label(card, text=info_text, style='Info.TLabel', justify='left')
        info_label.pack(anchor='w', padx=10, pady=3)
        
        # Encrypt button
        self.encrypt_button = tk.Button(card, text="🔒 ENCRYPT FILE", 
                                       bg=COLORS['accent'], fg=COLORS['fg'],
                                       font=('Segoe UI', 9, 'bold'), 
                                       relief='flat', cursor='hand2',
                                       padx=18, pady=8,
                                       command=self.start_encryption)
        self.encrypt_button.pack(pady=8)
        self.encrypt_button.bind('<Enter>', lambda e: self.encrypt_button.config(bg=COLORS['accent_hover']))
        self.encrypt_button.bind('<Leave>', lambda e: self.encrypt_button.config(bg=COLORS['accent']))
        
        # Variable for the file
        self.encrypt_file_path = None
    
    def create_decrypt_tab(self):
        """Create the decryption tab"""
        # Main card
        card = ttk.Frame(self.decrypt_tab, style='Card.TFrame')
        card.pack(fill='both', expand=True, padx=8, pady=8)
        
        # Title
        title = ttk.Label(card, text="Decrypt File", style='Subtitle.TLabel')
        title.pack(anchor='w', padx=10, pady=(8, 4))
        
        # Drop zone
        self.decrypt_drop_frame = tk.Frame(card, bg=COLORS['border'], height=80)
        self.decrypt_drop_frame.pack(fill='x', padx=10, pady=4)
        self.decrypt_drop_frame.pack_propagate(False)
        
        drop_label = tk.Label(self.decrypt_drop_frame, 
                             text="📁 Drag 3 files (.enc, .keys, .rsakey)",
                             bg=COLORS['card'], fg=COLORS['fg'], 
                             font=('Segoe UI', 9), cursor='hand2')
        drop_label.pack(expand=True, fill='both', padx=2, pady=2)
        drop_label.bind('<Button-1>', lambda e: self.select_decrypt_files())
        
        # Configure drag and drop
        try:
            self.decrypt_drop_frame.drop_target_register(DND_FILES)
            self.decrypt_drop_frame.dnd_bind('<<Drop>>', self.on_decrypt_drop)
        except:
            pass
        
        # Selected files with individual clear buttons
        files_frame = ttk.Frame(card, style='Main.TFrame')
        files_frame.pack(fill='x', padx=10, pady=2)
        
        # ENC file
        self.decrypt_enc_frame = ttk.Frame(files_frame, style='Main.TFrame')
        self.decrypt_enc_label = ttk.Label(self.decrypt_enc_frame, text="", style='Info.TLabel')
        self.decrypt_enc_clear = tk.Button(self.decrypt_enc_frame, text="✕", 
                                          bg=COLORS['error'], fg=COLORS['fg'],
                                          font=('Segoe UI', 7),
                                          relief='flat', cursor='hand2',
                                          padx=2, pady=0,
                                          command=lambda: self.clear_single_decrypt_file('enc'))
        
        # KEYS file
        self.decrypt_keys_frame = ttk.Frame(files_frame, style='Main.TFrame')
        self.decrypt_keys_label = ttk.Label(self.decrypt_keys_frame, text="", style='Info.TLabel')
        self.decrypt_keys_clear = tk.Button(self.decrypt_keys_frame, text="✕", 
                                           bg=COLORS['error'], fg=COLORS['fg'],
                                           font=('Segoe UI', 7),
                                           relief='flat', cursor='hand2',
                                           padx=2, pady=0,
                                           command=lambda: self.clear_single_decrypt_file('keys'))
        
        # RSAKEY file
        self.decrypt_rsakey_frame = ttk.Frame(files_frame, style='Main.TFrame')
        self.decrypt_rsakey_label = ttk.Label(self.decrypt_rsakey_frame, text="", style='Info.TLabel')
        self.decrypt_rsakey_clear = tk.Button(self.decrypt_rsakey_frame, text="✕", 
                                             bg=COLORS['error'], fg=COLORS['fg'],
                                             font=('Segoe UI', 7),
                                             relief='flat', cursor='hand2',
                                             padx=2, pady=0,
                                             command=lambda: self.clear_single_decrypt_file('rsakey'))
        
        # Status label for when no files are selected
        self.decrypt_no_files_label = ttk.Label(files_frame, text="No files selected", 
                                               style='Info.TLabel')
        self.decrypt_no_files_label.pack(anchor='w')
        
        # Information
        info_text = ("ℹ️ Required: .enc (encrypted), .keys (symmetric), .rsakey (private key)")
        info_label = ttk.Label(card, text=info_text, style='Info.TLabel', justify='left')
        info_label.pack(anchor='w', padx=10, pady=3)
        
        # Decrypt button
        self.decrypt_button = tk.Button(card, text="🔓 DECRYPT FILE", 
                                       bg=COLORS['success'], fg=COLORS['fg'],
                                       font=('Segoe UI', 9, 'bold'), 
                                       relief='flat', cursor='hand2',
                                       padx=18, pady=8,
                                       command=self.start_decryption)
        self.decrypt_button.pack(pady=8)
        self.decrypt_button.bind('<Enter>', lambda e: self.decrypt_button.config(bg='#3da88a'))
        self.decrypt_button.bind('<Leave>', lambda e: self.decrypt_button.config(bg=COLORS['success']))
        
        # Variables for the files
        self.decrypt_enc_path = None
        self.decrypt_keys_path = None
        self.decrypt_rsakey_path = None
    
    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    # ========== ENCRYPTION ==========
    
    def select_encrypt_file(self):
        """Allow selecting a file to encrypt"""
        file_path = filedialog.askopenfilename(title="Select a file to encrypt")
        if file_path:
            self.encrypt_file_path = file_path
            filename = os.path.basename(file_path)
            size = os.path.getsize(file_path)
            size_mb = size / (1024 * 1024)
            self.encrypt_file_label.config(
                text=f"✓ {filename} ({size_mb:.2f} MB)"
            )
            self.encrypt_clear_button.pack(side='left', padx=5)
    
    def on_encrypt_drop(self, event):
        """Handle the drag and drop event for encryption"""
        files = self.root.tk.splitlist(event.data)
        if files:
            file_path = files[0]
            if os.path.isfile(file_path):
                self.encrypt_file_path = file_path
                filename = os.path.basename(file_path)
                size = os.path.getsize(file_path)
                size_mb = size / (1024 * 1024)
                self.encrypt_file_label.config(
                    text=f"✓ {filename} ({size_mb:.2f} MB)"
                )
                self.encrypt_clear_button.pack(side='left', padx=5)
    
    def clear_encrypt_file(self):
        """Clear the selected encryption file"""
        self.encrypt_file_path = None
        self.encrypt_file_label.config(text="No file selected")
        self.encrypt_clear_button.pack_forget()
    
    def start_encryption(self):
        """Start the encryption process in a separate thread"""
        if not self.encrypt_file_path:
            messagebox.showwarning("Warning", "Please select a file to encrypt")
            return
        
        if not os.path.exists(self.encrypt_file_path):
            messagebox.showerror("Error", "The selected file does not exist")
            return
        
        if self.is_processing:
            messagebox.showwarning("Warning", "An operation is already in progress")
            return
        
        # Disable button
        self.encrypt_button.config(state='disabled')
        self.is_processing = True
        self.cancel_requested = False
        
        # Update status
        self.status_label.config(text="Encrypting file...", foreground=COLORS['warning'])
        self.progress_bar['mode'] = 'indeterminate'
        self.progress_bar.start(10)
        
        # Show cancel button
        self.cancel_button.pack(side='right', padx=5)
        
        # Run in separate thread
        thread = threading.Thread(target=self.run_encryption, daemon=True)
        thread.start()
    
    def run_encryption(self):
        """Execute encryption (in separate thread)"""
        try:
            success = aegis.encrypt_file(self.encrypt_file_path, cancel_callback=self.check_cancel)
            
            # Actualizar UI en el hilo principal
            self.root.after(0, lambda: self.on_encryption_complete(success))
        except Exception as e:
            self.root.after(0, lambda: self.on_encryption_error(str(e)))
    
    def on_encryption_complete(self, success):
        """Callback when encryption completes"""
        self.progress_bar.stop()
        self.progress_bar['mode'] = 'determinate'
        self.progress_bar['value'] = 100 if success else 0
        self.is_processing = False
        self.encrypt_button.config(state='normal')
        self.cancel_button.pack_forget()
        
        if self.cancel_requested:
            self.status_label.config(text="✗ Encryption cancelled", foreground=COLORS['warning'])
            self.encrypt_file_path = None
            self.encrypt_file_label.config(text="No file selected")
            self.encrypt_clear_button.pack_forget()
            return
        
        if success:
            self.status_label.config(text="✓ Encryption completed", foreground=COLORS['success'])
            
            base_name = os.path.splitext(self.encrypt_file_path)[0]
            enc_file = base_name + aegis.EXTENSION_ENC
            keys_file = base_name + aegis.EXTENSION_KEYS
            rsakey_file = base_name + aegis.EXTENSION_RSAKEY
            
            message = (f"File encrypted successfully!\n\n"
                      f"Generated files:\n"
                      f"• {os.path.basename(enc_file)}\n"
                      f"• {os.path.basename(keys_file)}\n"
                      f"• {os.path.basename(rsakey_file)}\n\n"
                      f"⚠️ IMPORTANT: Keep the .rsakey file safe.\n"
                      f"Without it, you CANNOT decrypt the file.")
            messagebox.showinfo("Encryption Completed", message)
            
            # Clear selection
            self.encrypt_file_path = None
            self.encrypt_file_label.config(text="No file selected")
            self.encrypt_clear_button.pack_forget()
        else:
            self.status_label.config(text="✗ Encryption error", foreground=COLORS['error'])
            messagebox.showerror("Error", "An error occurred during encryption. Check the console for details.")
    
    def on_encryption_error(self, error_msg):
        """Callback when there is an encryption error"""
        self.progress_bar.stop()
        self.progress_bar['mode'] = 'determinate'
        self.progress_bar['value'] = 0
        self.is_processing = False
        self.encrypt_button.config(state='normal')
        self.cancel_button.pack_forget()
        self.status_label.config(text="✗ Encryption error", foreground=COLORS['error'])
        if not self.cancel_requested:
            messagebox.showerror("Error", f"Error during encryption:\n{error_msg}")
    
    # ========== DECRYPTION ==========
    
    def select_decrypt_files(self):
        """Allow selecting files to decrypt"""
        files = filedialog.askopenfilenames(
            title="Select the 3 files (.enc, .keys, .rsakey)",
            filetypes=[("AEGIS Files", "*.enc *.keys *.rsakey"), ("All files", "*.*")]
        )
        
        if files:
            self.process_decrypt_files(files)
    
    def on_decrypt_drop(self, event):
        """Handle the drag and drop event for decryption"""
        files = self.root.tk.splitlist(event.data)
        if files:
            self.process_decrypt_files(files)
    
    def process_decrypt_files(self, files):
        """Process dragged/selected files for decryption"""
        # Identify each file
        for file_path in files:
            if not os.path.isfile(file_path):
                continue
            
            file_type = aegis.identify_file_type(file_path)
            
            if file_type == 'enc':
                self.decrypt_enc_path = file_path
            elif file_type == 'keys':
                self.decrypt_keys_path = file_path
            elif file_type == 'rsakey':
                self.decrypt_rsakey_path = file_path
        
        # Update display
        self.update_decrypt_files_display()
    
    def clear_single_decrypt_file(self, file_type):
        """Clear a single selected decryption file"""
        if file_type == 'enc':
            self.decrypt_enc_path = None
        elif file_type == 'keys':
            self.decrypt_keys_path = None
        elif file_type == 'rsakey':
            self.decrypt_rsakey_path = None
        
        self.update_decrypt_files_display()
    
    def update_decrypt_files_display(self):
        """Update the display of selected decryption files"""
        # Hide all frames first
        self.decrypt_enc_frame.pack_forget()
        self.decrypt_keys_frame.pack_forget()
        self.decrypt_rsakey_frame.pack_forget()
        self.decrypt_no_files_label.pack_forget()
        
        has_files = False
        
        # Show ENC file if selected
        if self.decrypt_enc_path:
            has_files = True
            self.decrypt_enc_label.config(text=f"✓ {os.path.basename(self.decrypt_enc_path)}")
            self.decrypt_enc_frame.pack(anchor='w', pady=1)
            self.decrypt_enc_label.pack(side='left')
            self.decrypt_enc_clear.pack(side='left', padx=5)
        
        # Show KEYS file if selected
        if self.decrypt_keys_path:
            has_files = True
            self.decrypt_keys_label.config(text=f"✓ {os.path.basename(self.decrypt_keys_path)}")
            self.decrypt_keys_frame.pack(anchor='w', pady=1)
            self.decrypt_keys_label.pack(side='left')
            self.decrypt_keys_clear.pack(side='left', padx=5)
        
        # Show RSAKEY file if selected
        if self.decrypt_rsakey_path:
            has_files = True
            self.decrypt_rsakey_label.config(text=f"✓ {os.path.basename(self.decrypt_rsakey_path)}")
            self.decrypt_rsakey_frame.pack(anchor='w', pady=1)
            self.decrypt_rsakey_label.pack(side='left')
            self.decrypt_rsakey_clear.pack(side='left', padx=5)
        
        # Show "no files" message if nothing selected
        if not has_files:
            self.decrypt_no_files_label.pack(anchor='w')
    
    def start_decryption(self):
        """Start the decryption process in a separate thread"""
        if not all([self.decrypt_enc_path, self.decrypt_keys_path, self.decrypt_rsakey_path]):
            messagebox.showwarning("Warning", 
                                 "Please select the 3 required files:\n"
                                 "• file.enc\n• file.keys\n• file.rsakey")
            return
        
        if self.is_processing:
            messagebox.showwarning("Warning", "An operation is already in progress")
            return
        
        # Disable button
        self.decrypt_button.config(state='disabled')
        self.is_processing = True
        self.cancel_requested = False
        
        # Update status
        self.status_label.config(text="Decrypting file...", foreground=COLORS['warning'])
        self.progress_bar['mode'] = 'indeterminate'
        self.progress_bar.start(10)
        
        # Show cancel button
        self.cancel_button.pack(side='right', padx=5)
        
        # Run in separate thread
        thread = threading.Thread(target=self.run_decryption, daemon=True)
        thread.start()
    
    def run_decryption(self):
        """Execute decryption (in separate thread)"""
        try:
            success = aegis.decrypt_file(
                self.decrypt_enc_path,
                self.decrypt_keys_path,
                self.decrypt_rsakey_path,
                cancel_callback=self.check_cancel
            )
            
            # Actualizar UI en el hilo principal
            self.root.after(0, lambda: self.on_decryption_complete(success))
        except Exception as e:
            self.root.after(0, lambda: self.on_decryption_error(str(e)))
    
    def on_decryption_complete(self, success):
        """Callback when decryption completes"""
        self.progress_bar.stop()
        self.progress_bar['mode'] = 'determinate'
        self.progress_bar['value'] = 100 if success else 0
        self.is_processing = False
        self.decrypt_button.config(state='normal')
        self.cancel_button.pack_forget()
        
        if self.cancel_requested:
            self.status_label.config(text="✗ Decryption cancelled", foreground=COLORS['warning'])
            self.decrypt_enc_path = None
            self.decrypt_keys_path = None
            self.decrypt_rsakey_path = None
            self.update_decrypt_files_display()
            return
        
        if success:
            self.status_label.config(text="✓ Decryption completed", foreground=COLORS['success'])
            messagebox.showinfo("Decryption Completed", 
                              "File decrypted successfully!\n\n"
                              "The original file has been recovered.")
            
            # Clear selection
            self.decrypt_enc_path = None
            self.decrypt_keys_path = None
            self.decrypt_rsakey_path = None
            self.update_decrypt_files_display()
        else:
            self.status_label.config(text="✗ Decryption error", foreground=COLORS['error'])
            messagebox.showerror("Error", 
                               "An error occurred during decryption.\n"
                               "Verify that:\n"
                               "• The files are correct\n"
                               "• The RSA key matches the encrypted file\n"
                               "• The files are not corrupted")
    
    def on_decryption_error(self, error_msg):
        """Callback when there is a decryption error"""
        self.progress_bar.stop()
        self.progress_bar['mode'] = 'determinate'
        self.progress_bar['value'] = 0
        self.is_processing = False
        self.decrypt_button.config(state='normal')
        self.cancel_button.pack_forget()
        self.status_label.config(text="✗ Decryption error", foreground=COLORS['error'])
        if not self.cancel_requested:
            messagebox.showerror("Error", f"Error during decryption:\n{error_msg}")


    def cancel_operation(self):
        """Cancel the current operation"""
        if self.is_processing:
            self.cancel_requested = True
            self.status_label.config(text="Cancelling...", foreground=COLORS['warning'])
    
    def check_cancel(self):
        """Check if cancellation was requested"""
        return self.cancel_requested
    
    def toggle_verbose_window(self):
        """Toggle the verbose mode window"""
        if self.verbose_window is None or not self.verbose_window.winfo_exists():
            self.create_verbose_window()
        else:
            self.close_verbose_window()
    
    def create_verbose_window(self):
        """Create the verbose mode window"""
        self.verbose_window = tk.Toplevel(self.root)
        self.verbose_window.title("AEGIS - Verbose Mode")
        self.verbose_window.geometry("800x500")
        self.verbose_window.configure(bg=COLORS['bg'])
        
        # Header
        header = ttk.Frame(self.verbose_window, style='Main.TFrame')
        header.pack(fill='x', padx=10, pady=10)
        
        title = ttk.Label(header, text="📋 Terminal Output (Verbose Mode)", style='Title.TLabel')
        title.pack(side='left')
        
        # Clear button
        clear_btn = tk.Button(header, text="🗑️ Clear", 
                             bg=COLORS['accent'], fg=COLORS['fg'],
                             font=('Segoe UI', 8, 'bold'),
                             relief='flat', cursor='hand2',
                             padx=10, pady=5,
                             command=self.clear_verbose_text)
        clear_btn.pack(side='right', padx=5)
        
        # Text widget with scrollbar
        text_frame = ttk.Frame(self.verbose_window, style='Main.TFrame')
        text_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side='right', fill='y')
        
        self.verbose_text = tk.Text(text_frame, 
                                   bg=COLORS['card'], fg=COLORS['fg'],
                                   font=('Consolas', 9),
                                   wrap='word',
                                   yscrollcommand=scrollbar.set,
                                   state='disabled')
        self.verbose_text.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.verbose_text.yview)
        
        # Configure text tags for colored output
        self.verbose_text.tag_config('error', foreground=COLORS['error'])
        self.verbose_text.tag_config('success', foreground=COLORS['success'])
        self.verbose_text.tag_config('warning', foreground=COLORS['warning'])
        self.verbose_text.tag_config('info', foreground='#f0f0f0')
        
        # Update button appearance (stays blue when active)
        self.verbose_button.config(bg=COLORS['accent_hover'])
        
        # Redirect stdout and stderr
        sys.stdout = VerboseRedirector(self.verbose_text, self.original_stdout)
        sys.stderr = VerboseRedirector(self.verbose_text, self.original_stderr, is_error=True)
        
        # Handle window close
        self.verbose_window.protocol("WM_DELETE_WINDOW", self.close_verbose_window)
        
        # Write initial message
        self.write_to_verbose("[Verbose Mode Activated]\n", 'info')
        self.write_to_verbose("All terminal output will be displayed here.\n\n", 'info')
    
    def close_verbose_window(self):
        """Close the verbose mode window"""
        if self.verbose_window and self.verbose_window.winfo_exists():
            # Restore original stdout/stderr
            sys.stdout = self.original_stdout
            sys.stderr = self.original_stderr
            
            # Update button appearance (back to normal blue)
            self.verbose_button.config(bg=COLORS['accent'])
            
            self.verbose_window.destroy()
            self.verbose_window = None
            self.verbose_text = None
    
    def clear_verbose_text(self):
        """Clear the verbose text widget"""
        if self.verbose_text:
            self.verbose_text.config(state='normal')
            self.verbose_text.delete('1.0', 'end')
            self.verbose_text.config(state='disabled')
    
    def write_to_verbose(self, text, tag=None):
        """Write text to the verbose window"""
        if self.verbose_text and self.verbose_text.winfo_exists():
            self.verbose_text.config(state='normal')
            if tag:
                self.verbose_text.insert('end', text, tag)
            else:
                self.verbose_text.insert('end', text)
            self.verbose_text.see('end')
            self.verbose_text.config(state='disabled')


def main():
    """Main function"""
    try:
        # Try to use TkinterDnD for drag and drop
        root = TkinterDnD.Tk()
    except:
        # If not available, use normal Tk
        root = tk.Tk()
        messagebox.showinfo("Information", 
                          "To enable drag and drop files, install:\n"
                          "pip install tkinterdnd2")
    
    app = AegisGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()

import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip
import re

class AdvancedPasswordGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Advanced Password Generator")
        self.root.geometry("600x700")
        self.root.resizable(True, True)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface."""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="🔐 Advanced Password Generator", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Password Length Section
        length_frame = ttk.LabelFrame(main_frame, text="Password Length", padding="10")
        length_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(length_frame, text="Length:").grid(row=0, column=0, sticky=tk.W)
        self.length_var = tk.IntVar(value=12)
        length_spinbox = ttk.Spinbox(length_frame, from_=4, to=128, width=10, 
                                   textvariable=self.length_var)
        length_spinbox.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        self.length_scale = ttk.Scale(length_frame, from_=4, to=128, orient=tk.HORIZONTAL,
                                    variable=self.length_var, length=300)
        self.length_scale.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Character Types Section
        char_frame = ttk.LabelFrame(main_frame, text="Character Types", padding="10")
        char_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.include_lowercase = tk.BooleanVar(value=True)
        self.include_uppercase = tk.BooleanVar(value=True)
        self.include_numbers = tk.BooleanVar(value=True)
        self.include_symbols = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(char_frame, text="Lowercase letters (a-z)", 
                       variable=self.include_lowercase).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(char_frame, text="Uppercase letters (A-Z)", 
                       variable=self.include_uppercase).grid(row=1, column=0, sticky=tk.W)
        ttk.Checkbutton(char_frame, text="Numbers (0-9)", 
                       variable=self.include_numbers).grid(row=2, column=0, sticky=tk.W)
        ttk.Checkbutton(char_frame, text="Symbols (!@#$...)", 
                       variable=self.include_symbols).grid(row=3, column=0, sticky=tk.W)
        
        # Security Rules Section
        security_frame = ttk.LabelFrame(main_frame, text="Security Rules", padding="10")
        security_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.avoid_ambiguous = tk.BooleanVar(value=True)
        self.ensure_complexity = tk.BooleanVar(value=True)
        self.no_repeating = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(security_frame, text="Avoid ambiguous characters (0, O, l, I)", 
                       variable=self.avoid_ambiguous).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(security_frame, text="Ensure complexity (at least one from each selected type)", 
                       variable=self.ensure_complexity).grid(row=1, column=0, sticky=tk.W)
        ttk.Checkbutton(security_frame, text="No repeating characters", 
                       variable=self.no_repeating).grid(row=2, column=0, sticky=tk.W)
        
        # Exclusion Section
        exclusion_frame = ttk.LabelFrame(main_frame, text="Character Exclusion", padding="10")
        exclusion_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(exclusion_frame, text="Exclude characters:").grid(row=0, column=0, sticky=tk.W)
        self.exclude_chars = tk.StringVar()
        exclude_entry = ttk.Entry(exclusion_frame, textvariable=self.exclude_chars, width=40)
        exclude_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 0))
        
        # Generate Button
        generate_btn = ttk.Button(main_frame, text="🎲 Generate Password", 
                                command=self.generate_password, style='Accent.TButton')
        generate_btn.grid(row=5, column=0, columnspan=2, pady=20)
        
        # Password Display Section
        display_frame = ttk.LabelFrame(main_frame, text="Generated Password", padding="10")
        display_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(display_frame, textvariable=self.password_var, 
                                 font=('Courier', 12), width=50, state='readonly')
        password_entry.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        copy_btn = ttk.Button(display_frame, text="📋 Copy", command=self.copy_password)
        copy_btn.grid(row=0, column=1, padx=(10, 0))
        
        # Password Analysis Section
        analysis_frame = ttk.LabelFrame(main_frame, text="Password Analysis", padding="10")
        analysis_frame.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.analysis_text = tk.Text(analysis_frame, height=6, width=60, state='disabled')
        self.analysis_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
    def generate_password(self):
        """Generate password based on current settings."""
        try:
            length = self.length_var.get()
            
            # Build character pool
            character_pool = ""
            required_chars = []
            
            if self.include_lowercase.get():
                chars = string.ascii_lowercase
                if self.avoid_ambiguous.get():
                    chars = chars.replace('l', '')
                character_pool += chars
                if self.ensure_complexity.get():
                    required_chars.append(random.choice(chars))
            
            if self.include_uppercase.get():
                chars = string.ascii_uppercase
                if self.avoid_ambiguous.get():
                    chars = chars.replace('O', '').replace('I', '')
                character_pool += chars
                if self.ensure_complexity.get():
                    required_chars.append(random.choice(chars))
            
            if self.include_numbers.get():
                chars = string.digits
                if self.avoid_ambiguous.get():
                    chars = chars.replace('0', '')
                character_pool += chars
                if self.ensure_complexity.get():
                    required_chars.append(random.choice(chars))
            
            if self.include_symbols.get():
                chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
                character_pool += chars
                if self.ensure_complexity.get():
                    required_chars.append(random.choice(chars))
            
            if not character_pool:
                messagebox.showerror("Error", "Please select at least one character type!")
                return
            
            # Remove excluded characters
            exclude_chars = self.exclude_chars.get()
            for char in exclude_chars:
                character_pool = character_pool.replace(char, '')
            
            if len(character_pool) == 0:
                messagebox.showerror("Error", "No characters available after exclusions!")
                return
            
            # Generate password
            if self.no_repeating.get() and length > len(character_pool):
                messagebox.showerror("Error", 
                    f"Cannot generate {length} character password without repeating characters. "
                    f"Maximum length with current settings: {len(character_pool)}")
                return
            
            if self.no_repeating.get():
                password_chars = random.sample(character_pool, length)
                password = ''.join(password_chars)
            else:
                # Start with required characters for complexity
                password_chars = required_chars[:]
                remaining_length = length - len(required_chars)
                
                # Fill remaining positions
                for _ in range(remaining_length):
                    password_chars.append(random.choice(character_pool))
                
                # Shuffle to avoid predictable patterns
                random.shuffle(password_chars)
                password = ''.join(password_chars)
            
            self.password_var.set(password)
            self.analyze_password(password)
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def analyze_password(self, password):
        """Analyze password strength and characteristics."""
        self.analysis_text.config(state='normal')
        self.analysis_text.delete(1.0, tk.END)
        
        analysis = []
        analysis.append(f"Length: {len(password)} characters")
        
        # Character type analysis
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        
        char_types = []
        if has_lower: char_types.append("lowercase")
        if has_upper: char_types.append("uppercase")
        if has_digit: char_types.append("numbers")
        if has_symbol: char_types.append("symbols")
        
        analysis.append(f"Character types: {', '.join(char_types)}")
        
        # Strength calculation
        strength_score = 0
        if len(password) >= 8: strength_score += 1
        if len(password) >= 12: strength_score += 1
        if len(password) >= 16: strength_score += 1
        if has_lower: strength_score += 1
        if has_upper: strength_score += 1
        if has_digit: strength_score += 1
        if has_symbol: strength_score += 1
        
        strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong", "Excellent"]
        strength = strength_levels[min(strength_score, 6)]
        analysis.append(f"Strength: {strength} ({strength_score}/7)")
        
        # Entropy calculation
        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_symbol: charset_size += 23
        
        if charset_size > 0:
            import math
            entropy = len(password) * math.log2(charset_size)
            analysis.append(f"Entropy: {entropy:.1f} bits")
        
        self.analysis_text.insert(tk.END, '\n'.join(analysis))
        self.analysis_text.config(state='disabled')
    
    def copy_password(self):
        """Copy password to clipboard."""
        password = self.password_var.get()
        if password:
            try:
                pyperclip.copy(password)
                messagebox.showinfo("Success", "Password copied to clipboard!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to copy to clipboard: {str(e)}")
        else:
            messagebox.showwarning("Warning", "No password to copy!")

def main():
    """Main function for the advanced password generator."""
    root = tk.Tk()
    app = AdvancedPasswordGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()

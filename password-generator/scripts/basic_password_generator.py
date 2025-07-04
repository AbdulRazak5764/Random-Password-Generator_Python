import random
import string

def generate_password(length, include_letters=True, include_numbers=True, include_symbols=True):
    """
    Generate a random password based on specified criteria.
    
    Args:
        length (int): Length of the password
        include_letters (bool): Include letters (a-z, A-Z)
        include_numbers (bool): Include numbers (0-9)
        include_symbols (bool): Include symbols (!@#$%^&*)
    
    Returns:
        str: Generated password
    """
    character_pool = ""
    
    if include_letters:
        character_pool += string.ascii_letters  # a-z, A-Z
    if include_numbers:
        character_pool += string.digits  # 0-9
    if include_symbols:
        character_pool += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if not character_pool:
        raise ValueError("At least one character type must be selected!")
    
    # Generate password
    password = ''.join(random.choice(character_pool) for _ in range(length))
    return password

def validate_input(prompt, input_type=int, min_val=None, max_val=None):
    """
    Validate user input with type checking and range validation.
    """
    while True:
        try:
            value = input_type(input(prompt))
            if min_val is not None and value < min_val:
                print(f"Value must be at least {min_val}")
                continue
            if max_val is not None and value > max_val:
                print(f"Value must be at most {max_val}")
                continue
            return value
        except ValueError:
            print(f"Please enter a valid {input_type.__name__}")

def get_yes_no_input(prompt):
    """
    Get yes/no input from user.
    """
    while True:
        response = input(prompt).lower().strip()
        if response in ['y', 'yes', '1', 'true']:
            return True
        elif response in ['n', 'no', '0', 'false']:
            return False
        else:
            print("Please enter 'y' for yes or 'n' for no")

def main():
    """
    Main function for the basic password generator.
    """
    print("🔐 Python Password Generator - Basic Version")
    print("=" * 50)
    
    while True:
        try:
            # Get password length
            length = validate_input(
                "Enter password length (4-128): ", 
                int, 
                min_val=4, 
                max_val=128
            )
            
            # Get character type preferences
            print("\nCharacter type preferences:")
            include_letters = get_yes_no_input("Include letters (a-z, A-Z)? (y/n): ")
            include_numbers = get_yes_no_input("Include numbers (0-9)? (y/n): ")
            include_symbols = get_yes_no_input("Include symbols (!@#$...)? (y/n): ")
            
            # Generate password
            password = generate_password(length, include_letters, include_numbers, include_symbols)
            
            print(f"\n✅ Generated Password: {password}")
            print(f"Password Length: {len(password)}")
            
            # Analyze password strength
            strength_score = 0
            if include_letters: strength_score += 1
            if include_numbers: strength_score += 1
            if include_symbols: strength_score += 1
            if length >= 12: strength_score += 1
            if length >= 16: strength_score += 1
            
            strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
            strength = strength_levels[min(strength_score, 4)]
            print(f"Password Strength: {strength}")
            
        except ValueError as e:
            print(f"❌ Error: {e}")
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        
        # Ask if user wants to generate another password
        if not get_yes_no_input("\nGenerate another password? (y/n): "):
            print("👋 Thank you for using the Password Generator!")
            break

if __name__ == "__main__":
    main()

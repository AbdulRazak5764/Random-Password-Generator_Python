import re
import math

def check_password_strength(password):
    """
    Comprehensive password strength checker.
    
    Args:
        password (str): Password to analyze
    
    Returns:
        dict: Analysis results including score, strength level, and recommendations
    """
    analysis = {
        'password': password,
        'length': len(password),
        'score': 0,
        'max_score': 10,
        'strength': 'Very Weak',
        'characteristics': {},
        'recommendations': [],
        'entropy': 0
    }
    
    # Length analysis
    if analysis['length'] >= 8:
        analysis['score'] += 1
    if analysis['length'] >= 12:
        analysis['score'] += 1
    if analysis['length'] >= 16:
        analysis['score'] += 1
    
    # Character type analysis
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
    
    analysis['characteristics'] = {
        'lowercase': has_lower,
        'uppercase': has_upper,
        'digits': has_digit,
        'symbols': has_symbol
    }
    
    # Score for character diversity
    char_types = sum([has_lower, has_upper, has_digit, has_symbol])
    analysis['score'] += char_types
    
    # Check for common patterns (negative points)
    common_patterns = [
        r'123', r'abc', r'qwerty', r'password', r'admin',
        r'(.)\1{2,}',  # Repeating characters
        r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)'  # Sequential letters
    ]
    
    pattern_found = False
    for pattern in common_patterns:
        if re.search(pattern, password.lower()):
            pattern_found = True
            break
    
    if not pattern_found:
        analysis['score'] += 1
    
    # Entropy calculation
    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_symbol: charset_size += 23
    
    if charset_size > 0:
        analysis['entropy'] = len(password) * math.log2(charset_size)
    
    # Determine strength level
    if analysis['score'] <= 2:
        analysis['strength'] = 'Very Weak'
    elif analysis['score'] <= 4:
        analysis['strength'] = 'Weak'
    elif analysis['score'] <= 6:
        analysis['strength'] = 'Fair'
    elif analysis['score'] <= 8:
        analysis['strength'] = 'Good'
    elif analysis['score'] <= 9:
        analysis['strength'] = 'Strong'
    else:
        analysis['strength'] = 'Very Strong'
    
    # Generate recommendations
    if analysis['length'] < 8:
        analysis['recommendations'].append("Use at least 8 characters")
    if analysis['length'] < 12:
        analysis['recommendations'].append("Consider using 12+ characters for better security")
    if not has_lower:
        analysis['recommendations'].append("Include lowercase letters")
    if not has_upper:
        analysis['recommendations'].append("Include uppercase letters")
    if not has_digit:
        analysis['recommendations'].append("Include numbers")
    if not has_symbol:
        analysis['recommendations'].append("Include symbols (!@#$...)")
    if pattern_found:
        analysis['recommendations'].append("Avoid common patterns and sequences")
    if char_types < 3:
        analysis['recommendations'].append("Use at least 3 different character types")
    
    return analysis

def main():
    """Main function for password strength checker."""
    print("🔍 Password Strength Checker")
    print("=" * 40)
    
    while True:
        password = input("\nEnter password to analyze (or 'quit' to exit): ")
        
        if password.lower() == 'quit':
            print("👋 Goodbye!")
            break
        
        if not password:
            print("❌ Please enter a password")
            continue
        
        analysis = check_password_strength(password)
        
        print(f"\n📊 Password Analysis Results:")
        print(f"Password: {'*' * len(password)}")
        print(f"Length: {analysis['length']} characters")
        print(f"Strength: {analysis['strength']} ({analysis['score']}/{analysis['max_score']})")
        print(f"Entropy: {analysis['entropy']:.1f} bits")
        
        print(f"\n✅ Character Types:")
        for char_type, present in analysis['characteristics'].items():
            status = "✓" if present else "✗"
            print(f"  {status} {char_type.capitalize()}")
        
        if analysis['recommendations']:
            print(f"\n💡 Recommendations:")
            for i, rec in enumerate(analysis['recommendations'], 1):
                print(f"  {i}. {rec}")
        else:
            print(f"\n🎉 Excellent! Your password meets all security criteria.")

if __name__ == "__main__":
    main()

import string

# Configuration
shift = 3
letters = string.ascii_letters + string.punctuation + string.digits

# Input choices
choice = input("Would you like to encode or decode? ").strip().lower()
word = input("Please enter text: ").strip()

# Initialize encoded/decoded result
encoded = ''

# Caesar Cipher Encoding/Decoding
if choice == "encode":
    for letter in word:
        if letter == ' ':
            encoded += ' '  # Preserve spaces
        elif letter in letters:
            x = (letters.index(letter) + shift) % len(letters)  # Ensure wrapplicationlicationing
            encoded += letters[x]
        else:
            encoded += letter  # Leave unsupported characters as is
elif choice == "decode":
    for letter in word:
        if letter == ' ':
            encoded += ' '  # Preserve spaces
        elif letter in letters:
            x = (letters.index(letter) - shift) % len(letters)  # Ensure wrapplicationlicationing
            encoded += letters[x]
        else:
            encoded += letter  # Leave unsupported characters as is
else:
    print("Invalid choice. Please choose 'encode' or 'decode'.")

# Output result
if encoded:
    print(f"Result: {encoded}")
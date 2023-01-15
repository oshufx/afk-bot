import hashlib
import getpass

# Create a dictionary to store username and hashed password
passwords = {}

def create_account():
    print("Creating a new account...")
    username = input("Enter a username: ")
    password = getpass.getpass("Enter a password: ")
    # Hash the password using SHA-256
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    # Add the username and hashed password to the dictionary
    passwords[username] = hashed_password
    print("Account created!")

def login():
    print("Logging in...")
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    # Hash the entered password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    # Check if the entered username and password match the stored values
    if username in passwords and passwords[username] == hashed_password:
        print("Login successful!")
    else:
        print("Invalid username or password.")

def main():
    while True:
        print("Welcome to the password manager.")
        print("1. Create an account")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            create_account()
        elif choice == "2":
            login()
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
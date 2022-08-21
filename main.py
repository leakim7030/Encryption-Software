import sqlite3
import random

# Global variable
chars = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k",
         "l", "m", "n", "o", "p", "q", "r", "s", "t"
    , "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
         "Q", "R", "S"
    , "T", "U", "V", "W", "X", "Y", "Z", "æ", "Æ", "ø", "Ø", "å", "Å", ".", ",", "-", "!", "?", "|", "+", "$", "{", "}", "%", "€", "*", " "]


def create_keys():
    charsFunc = chars
    length_chars = len(chars)
    key = []

    while len(key) != length_chars:
        for i in range(0, length_chars):
            random_number = random.randint(0, len(charsFunc) - 1)
            if charsFunc[random_number] not in key:
                key.append(charsFunc[random_number])
                charsFunc.remove(charsFunc[random_number])
            else:
                print("Something happened while creating keys")
                break

    to_string = "".join(key)

    return to_string


def encrypt_message(message, which_key):

    charsFunc = chars
    longList = []
    for char in charsFunc:
        if char in message:
            longList.append(charsFunc.index(char))

    encrypted_message = ""
    key = get_key(which_key)[0]

    for a in message:
        for b in longList:
            if a == charsFunc[b]:
                encrypted_message += key[b]

    sql = '''Insert into Messages (Message,keyId)
            Values (
            ?, ?
            );'''

    print(encrypted_message)
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (encrypted_message, which_key))

        conn.commit()
        cursor.close()
        return encrypted_message
    except:
        print("Error adding message to DB")


def Generate_password(domain, password_length, username): # , which_key REMOVED

    charsFunc = chars

    password = ""

    for a in range(password_length):
        password += charsFunc[random.randint(0, len(charsFunc) - 1)]

    sql = '''Insert into Passwords (Domain, Password, UserName)
            Values (
            ?, ?, ?
            );
    ''' # , KeyId REMOVED
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (domain, password, username)) # , which_key REMOVED
        conn.commit()
        cursor.close()
        print(f"\nGood job '{username}' on securing your password for '{domain}' you can access it by using the "
              f"retrieve password function\n")

        conn.commit()

    except:
        print("\nERROR MESSAGE: Either caused by updating password (Not an issue), or unique Domain constraint "
              "stopped from adding duplicates, or it might be something else, use retrieve "
              "password function\n")

    return password

def locks_to_db(how_many_locks):
    how_many_locks = 1 # Hardcoded because of error while adding more than one lock
    cursor = conn.cursor()
    keys = []
    for i in range(how_many_locks):
        keys.append(create_keys())

    sql = '''INSERT INTO Keys (Key)
            VALUES (?);
    '''
    for key in keys:
        cursor.execute(sql, [str(key), ])
    conn.commit()
    cursor.close()


def get_key(key):
    print(key)
    cursor = conn.cursor()
    sql = '''select Key
    from Keys
    where keyId = ?;'''
    result = cursor.execute(sql, (str(key), )).fetchall()
    cursor.close()

    result = list(result[0])

    return result


def decrypt_message(encrypted_message_input, which_key):

    charsFunc = chars
    encrypted_message = list(encrypted_message_input)
    key = get_key(which_key)

    longList = []
    for char in key:
        if char in encrypted_message:
            longList.append(key.index(char))

    decrypted_message = ""

    for a in encrypted_message:
        for b in longList:
            if a == key[b]:
                decrypted_message += charsFunc[b]

    return decrypted_message


def retrieve_password(domain):

    sql = '''Select Domain, UserName, Password
            From Passwords P
            
            where P.Domain = ?;
            
    '''
    try:
        cursor = conn.cursor()

        result = cursor.execute(sql, (domain,)).fetchall()

        cursor.close()
        return f"\nUSERNAME -- {result[0][1]} -- PASSWORD -- {result[0][2]} --\n"
    except : print("Error occured while trying to retrieve password")


def add_pincode(pin):

    sql = ''' Insert into Pin(PinCode)
        values(?);
    '''

    cursor = conn.cursor()

    cursor.execute(sql, (pin,))
    conn.commit()
    cursor.close()


def add_security_questions(aDict):

    sql = ''' Insert into SecurityQuestions(SecurityQuestion,SecurityAnswer)
            values(?,?);
    '''
    cursor = conn.cursor()

    for key_value in aDict:
        cursor.execute(sql, (key_value, aDict[key_value],))
    conn.commit()
    cursor.close()

def setup_pin_questions():

    security_question_dict = dict()
    print("\nWelcome to the * Password Manager Software * You are now required to setup a Pin Code and some security questions \n ")
    while 1:
        while 1:
            pin_code = int(input("Enter a 4 digit pin code: "))
            if 1000 <= pin_code <= 9999:
                break
        while 1:
            security_question1 = "In what city were you born? "
            security_answer1 = str(input(security_question1))
            if len(security_answer1) > 1:
                security_question_dict[security_question1] = security_answer1
                break
        while 1:
            security_question2 = "What is your nickname? "
            security_answer2 = str(input(security_question2))
            if len(security_answer2) > 1:
                security_question_dict[security_question2] = security_answer2
                break
        while 1:
            security_question3 = "What was the name of the first school you went to? "
            security_answer3 = str(input(security_question3))
            if len(security_answer3) > 1:
                security_question_dict[security_question3] = security_answer3
                break
        while 1:
            security_question4 = "What was your favorite food as a child? "
            security_answer4 = str(input(security_question4))
            if len(security_answer4) > 1:
                security_question_dict[security_question4] = security_answer4
                break
        while 1:
            security_question5 = "Who was your best friend as a child? "
            security_answer5 = str(input(security_question5))
            if len(security_answer5) > 1:
                security_question_dict[security_question5] = security_answer5
                break

        print(f"\nPin code is now '{pin_code}'\n"
              f"Security question 1: In what city were you born? - {security_answer1}\n"
              f"Security question 2: What is your nickname? - {security_answer2}\n"
              f"Security question 3: What was the name of the first school you went to? - {security_answer3}\n"
              f"Security question 4: What was your favorite food as a child? - {security_answer4} \n"
              f"Security question 5: Who was your best friend as a child? - {security_answer5} \n\n"
              f"Happy with these answers? Yes or No?\n")

        if str(input()).lower() == "yes":
            add_pincode(pin_code)
            add_security_questions(security_question_dict)
            break

def initial_setup_completed(): #Check if there exists a pin and security questions

    sql = '''Select pinCode
        from Pin;
    '''
    cursor = conn.cursor()

    result = cursor.execute(sql).fetchone()

    if result == None:
        setup_pin_questions()
    else:
        validate_pin_questions()

    cursor.close()

def update_password(domain, username):

    sql = ''' Update Passwords
            set Password = ?
            where domain = ? and username = ?;      
    '''
    #
    cursor = conn.cursor()
    new_password = Generate_password(domain, 15, username)

    cursor.execute(sql,(new_password,domain, username,))
    conn.commit()
    cursor.close()

    print(f"\nPassword for {username} on {domain} is sucessfully updated\n")
    # except:
    #     print("Error updating the password")

def find_all_accounts():
    sql = ''' Select domain, username
            From Passwords;
    '''
    cursor = conn.cursor()
    result = cursor.execute(sql).fetchall()
    for r in result:
        print(f"{r[0].upper()} - {r[1]}" )

def validate_pin_questions():

    sql_pin = '''Select PinCode
            From Pin;
    '''
    cursor = conn.cursor()

    pin_code_db = cursor.execute(sql_pin,).fetchone()

    sql_security_questions = '''select SecurityQuestion, SecurityAnswer
                            from SecurityQuestions;
    '''

    sql_security_questions_db = cursor.execute((sql_security_questions)).fetchall()

    random_question = random.randint(0,len(sql_security_questions_db))

    correct = False

    while not correct:

        pin_code_validate = int(input("Enter Pin Code: "))


        if pin_code_db[0] == pin_code_validate:

            security_question_validate = str(input(f"{sql_security_questions_db[random_question - 1][0]}"))

            if security_question_validate == sql_security_questions_db[random_question - 1][1]:
                correct = True

        else:
            break
def check_if_key_exists(keyid):
    sql = '''select *
            from Keys
            where KeyId = ?;
    '''
    cursor = conn.cursor()
    result = cursor.execute(sql,(keyid,)).fetchall()
    cursor.close()
    if len(result) >= 1:
        return True
    else:
        return False
def last_key_inserted():
    sql = '''select keyId
            from Keys
            order by keyId DESC;
    '''
    cursor = conn.cursor()
    result = cursor.execute(sql,).fetchone()
    cursor.close()
    return str(result[0])
    #####

def check_keys():
    sql = '''select *
    from Keys
    '''
    cursor = conn.cursor()
    result = cursor.execute(sql,).fetchall()
    cursor.close()

    for key in result:
        print(key)



# Press the green button in the gutter to run the script.
if __name__ == '__main__':

    conn = sqlite3.connect('cryptography.db')
    cursor = conn.cursor()

    # Creating or checking if necessary tables exist
    try:
        cursor.execute('''CREATE TABLE Keys
        (keyId INTEGER PRIMARY KEY AUTOINCREMENT,
        Key TEXT NOT NULL);
        ''')
    except:
        print("INFO: Table Keys already exists")
    try: #Kan endre på keyId til TEXT, uten NOT NULL, det gjør at du ikke trenger referanser til
        cursor.execute('''CREATE TABLE Passwords
        (passwordId INTEGER PRIMARY KEY AUTOINCREMENT,
        Domain TEXT NOT NULL,
        Password TEXT NOT NULL,
        userName TEXT NOT NULL,
        Unique (Domain)
        );
        ''')
    except:
        print("INFO: Table Passwords already exists")

    try:
        cursor.execute('''CREATE TABLE Messages
        (messageId INTEGER PRIMARY KEY AUTOINCREMENT,
        Message TEXT NOT NULL,
        keyId INTEGER NOT NULL,
        unique (Message, keyId),
            FOREIGN KEY (keyId)
            REFERENCES Keys (keyId) );
        ''')
    except:
        print("INFO: Table Messages already exists")

    try:
        cursor.execute('''CREATE TABLE SecurityQuestions
        (SecurityQuestion TEXT NOT NULL,
        SecurityAnswer TEXT NOT NULL,
        unique (SecurityQuestion));

        ''')
    except:
        print("INFO: Table SecurityQuestions already exists")

    try:
        cursor.execute('''CREATE TABLE Pin
        (PinCode INT NOT NULL);

        ''')
    except:
        print("INFO: Table Pin already exists")

    # INITIALISE THIS FUNCTION TO CREATE A LIST OF LOCKS AND INSERT INTO DB

    #############START PROGRAM HERE#########
    conn.commit()
    cursor.close()

    initial_setup_completed()

    while 1:

        print("\nWhat would you like to do?\n\n")
        print("1. Change Pin Code and security questions")
        print("2. Generate new keys for encrpyted messages")
        print("3. Store a new password")
        print("4. Retrieve password and username")
        print("5. Update password")
        print("6. Find all accounts")
        print("7. Encrypt message")
        # print("8. Decrypt message with key")'
        print("0. Exit program")

        first_choice = int(input())
        # INITIAL SETUP
        if first_choice == 1: # TO BE CHANGE PIN CODE
            setup_pin_questions()

        elif first_choice == 2: # Generate unique keys
            how_many_locks = 0
            while how_many_locks not in range(1, 1000):
                try:
                    how_many_locks = int(input("Enter a number of keys "))
                except ValueError:
                    print("Must be numbers and between 1-999")
            locks_to_db(how_many_locks)

        elif first_choice == 3: # store a new password for a domain
            domain_input = str(input("Enter a domain, E.g Facebook: ")).lower()
            password_length_input = int(input("Enter a password length: "))
            username_input = str(input(("Enter a username: "))).lower()
            #input("To which lock/code e.g you have 100 locks, and now select lock 30) do you want: "))
            Generate_password(domain_input, password_length_input, username_input) # , which_key_input REMOVED

        elif first_choice == 4: # show password for a domain
            domain_input_retrieve = str(input("Enter a domain, E.g Facebook: ")).lower()
            print(retrieve_password(domain_input_retrieve))

        elif first_choice == 5: # change password for a domain
            password_change_domain = str(input("Which domain would you like to update password for: "))
            password_change_username = str(input(f"What is the username for {password_change_domain}? "))
            update_password(password_change_domain,password_change_username)

        elif first_choice == 6: # find all accounts
            find_all_accounts()

        elif first_choice == 7: # encrypt message
            message_to_encrypt = str(input("Enter a message to encrypt: "))
            while 1:
                which_key_id = str(input('''\nWhich key-Id would you like to use? If you have not created a key yet,
use the generate keys function first (press 0 and enter): '''))
                if check_if_key_exists(which_key_id) == True and which_key_id != 0:
                    False
                    message_show = encrypt_message(message_to_encrypt, which_key_id)
                    print(f"\n--- Encrypted Message --- \n{message_show} \n")
                    break
                elif which_key_id == str("0"):
                    locks_to_db(1)
                    print(f" This is the keyId you created: {last_key_inserted()}")
                else:
                    print("\nYou need to generate a new key, or select another one")
        elif first_choice == 8:
            check_keys()








        elif first_choice == 0:
            False
            break


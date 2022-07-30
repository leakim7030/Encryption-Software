import sqlite3
import random

# to do--
# add database encryption (sqlcipher)
# add more functionality


# Global variable
chars = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k",
         "l", "m", "n", "o", "p", "q", "r", "s", "t"
    , "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
         "Q", "R", "S"
    , "T", "U", "V", "W", "X", "Y", "Z", ".", ",", "-", "!", "?", "|", "+", "$", "{", "}", "%", "€", "*", " "]


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
    key = get_key(which_key)

    for a in message:
        for b in longList:
            if a == charsFunc[b]:
                encrypted_message += key[b]

    sql = '''Insert into Messages (Message,keyId)
            Values (
            ?, ?
            );'''
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (encrypted_message, which_key))

        conn.commit()
        cursor.close()
    except:
        print("Error adding message to DB")


def Generate_password(domain, password_length, username, which_key):
    charsFunc = chars

    password = ""
    key = get_key(which_key)

    for a in range(password_length):
        password += charsFunc[random.randint(0, len(charsFunc) - 1)]

    sql = '''Insert into Passwords (Domain, Password, UserName, KeyId)
            Values (
            ?, ?, ?, ?
            );
    '''
    try:
        cursor = conn.cursor()
        cursor.execute(sql, (domain, password, username, which_key))
        conn.commit()
        cursor.close()
        print(f"\nGood job '{username}' on securing your password for '{domain}' you can access it by using the "
              f"retrieve password function\n")

        conn.commit()
        print("Password saved")
    except:
        print("Error adding password to DB")


def locks_to_db(how_many_locks):
    cursor = conn.cursor()
    keys = [create_keys() for i in range(how_many_locks)]
    sql = '''INSERT INTO Keys (Key)
            VALUES (?);
    '''
    for key in keys:
        cursor.execute(sql, [str(key), ])
    conn.commit()
    cursor.close()


def get_key(key):
    cursor = conn.cursor()
    sql = '''select Key
    from Keys
    where keyId = ?'''
    result = cursor.execute(sql, [str(key), ]).fetchone()
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
            
            inner join Keys K
            on P.KeyId = K.KeyId
            
            where P.Domain = ?;
            
    '''
    cursor = conn.cursor()

    result = cursor.execute(sql, (domain,)).fetchall()

    cursor.close()
    print(result)
    return f"\nUSERNAME -- {result[0][1]} -- PASSWORD -- {result[0][2]} --\n"


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

def initial_setup_completed():
    sql = '''Select pinCode
        from Pin
    '''
    cursor = conn.cursor()

    result = cursor.execute(sql).fetchone()

    if result == None:
        setup_pin_questions()
    else:
        validate_pin_questions()

    cursor.close()

def update_password(domain, username):
    print()

def validate_pin_questions():



    sql_pin = '''Select PinCode
            From Pin
    '''
    cursor = conn.cursor()


    pin_code_db = cursor.execute(sql_pin,).fetchone()

    sql_security_questions = '''select SecurityQuestion, SecurityAnswer
                            from SecurityQuestions
    '''

    sql_security_questions_db = cursor.execute((sql_security_questions)).fetchall()

    random_question = random.randint(0,len(sql_security_questions_db))

    correct = False
                            #### IKKE FERDIG
    while not correct:

        pin_code_validate = int(input("Enter Pin Code: "))


        if pin_code_db[0] == pin_code_validate:

            security_question_validate = str(input(f"{sql_security_questions_db[random_question - 1][0]}"))

            if security_question_validate == sql_security_questions_db[random_question - 1][1]:
                correct = True

        else:
            break
                                #####


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
        keyId INTEGER NOT NULL,
            FOREIGN KEY (keyId)
            REFERENCES Keys (keyId) );
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
        print("1. Change Pin Code")
        print("2. Generate new keys for encrpyted messages (needs to happen at least once with at least one, max 1 000 keys per add) ")
        print("3. Store a new password")
        print("4. Retrieve password")
        print("5. Update password")
        print("0. Exit program")

        first_choice = int(input())
        # INITIAL SETUP
        if first_choice == 1: # TO BE CHANGE PIN CODE
            setup_pin_questions()

        # Generate unique keys
        elif first_choice == 2:
            how_many_locks = 0
            while how_many_locks not in range(1, 1000):
                try:
                    how_many_locks = int(input("Enter a number of keys "))
                except ValueError:
                    print("Must be numbers and between 1-999")
            locks_to_db(how_many_locks)

        elif first_choice == 3:
            domain_input = str(input("Enter a domain, E.g Facebook: ")).lower()
            password_length_input = int(input("Enter a password length: "))
            username_input = str(input(("Enter a username: "))).lower()
            which_key_input = int(
                input("To which lock/code e.g you have 100 locks, and now select lock 30) do you want: "))
            Generate_password(domain_input, password_length_input, username_input, which_key_input)

        elif first_choice == 4:
            domain_input_retrieve = str(input("Enter a domain, E.g Facebook: ")).lower()
            print(retrieve_password(domain_input_retrieve))

        elif first_choice == 5:
            password_change_domain = str(input("Which domain would you like to update: "))


        elif first_choice == 0:
            False
            break


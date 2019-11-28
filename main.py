# import modules

from tkinter import *
import hashlib, binascii, os


def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')


def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512',
                                  provided_password.encode('utf-8'),
                                  salt.encode('ascii'),
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password


list_common_pws = ['123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein', '696969', 'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang', '1234567890', 'michael', '654321', 'pussy', 'superman', '1qaz2wsx', '7777777', 'fuckyou', '121212', '000000', 'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', 'fuckme', '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars', 'klaster', '112233', 'george', 'asshole', 'computer', 'michelle', 'jessica', 'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313', 'freedom', '777777', 'pass', 'fuck', 'maggie', '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love', 'ashley', '6969', 'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees', '987654321', 'dallas', 'austin', 'thunder', 'taylor', 'matrix', 'william', 'corvette', 'hello', 'martin', 'heather', 'secret', 'fucker', 'merlin', 'diamond', '1234qwer', 'gfhjkm', 'hammer', 'silver', '222222', '88888888', 'anthony', 'justin', 'test', 'bailey', 'q1w2e3r4t5', 'patrick', 'internet', 'scooter', 'orange', '11111', 'golfer', 'cookie', 'richard', 'samantha', 'bigdog', 'guitar', 'jackson', 'whatever', 'mickey', 'chicken', 'sparky', 'snoopy', 'maverick', 'phoenix', 'camaro', 'sexy', 'peanut', 'morgan', 'welcome', 'falcon', 'cowboy', 'ferrari', 'samsung', 'andrea', 'smokey', 'steelers', 'joseph', 'mercedes', 'dakota', 'arsenal', 'eagles', 'melissa', 'boomer', 'booboo', 'spider', 'nascar', 'monster', 'tigers', 'yellow', 'xxxxxx', '123123123', 'gateway', 'marina', 'diablo', 'bulldog', 'qwer1234', 'compaq', 'purple', 'hardcore', 'banana', 'junior', 'hannah', '123654', 'porsche', 'lakers', 'iceman', 'money', 'cowboys', '987654', 'london', 'tennis', '999999', 'ncc1701', 'coffee', 'scooby', '0000', 'miller', 'boston', 'q1w2e3r4', 'fuckoff', 'brandon', 'yamaha', 'chester', 'mother', 'forever', 'johnny', 'edward', '333333', 'oliver', 'redsox', 'player', 'nikita', 'knight', 'fender', 'barney', 'midnight', 'please', 'brandy', 'chicago', 'badboy', 'iwantu', 'slayer', 'rangers', 'charles', 'angel', 'flower', 'bigdaddy', 'rabbit', 'wizard', 'bigdick', 'jasper', 'enter', 'rachel', 'chris', 'steven', 'winner', 'adidas', 'victoria', 'natasha', '1q2w3e4r', 'jasmine', 'winter', 'prince', 'panties', 'marine', 'ghbdtn', 'fishing', 'cocacola', 'casper', 'james', '232323', 'raiders', '888888', 'marlboro', 'gandalf', 'asdfasdf', 'crystal', '87654321', '12344321', 'sexsex', 'golden', 'blowme', 'bigtits', '8675309', 'panther', 'lauren', 'angela', 'bitch', 'spanky', 'thx1138', 'angels', 'madison', 'winston', 'shannon', 'mike', 'toyota', 'blowjob', 'jordan23', 'canada', 'sophie', 'Password', 'apples', 'dick', 'tiger', 'razz', '123abc', 'pokemon', 'qazxsw', '55555', 'qwaszx', 'muffin', 'johnson', 'murphy', 'cooper', 'jonathan', 'liverpoo', 'david', 'danielle', '159357', 'jackie', '1990', '123456a', '789456', 'turtle', 'horny', 'abcd1234', 'scorpion', 'qazwsxedc', '101010', 'butter', 'carlos', 'password1', 'dennis', 'slipknot', 'qwerty123', 'booger', 'asdf', '1991', 'black', 'startrek', '12341234', 'cameron', 'newyork', 'rainbow', 'nathan', 'john', '1992', 'rocket', 'viking', 'redskins', 'butthead', 'asdfghjkl', '1212', 'sierra', 'peaches', 'gemini', 'doctor', 'wilson', 'sandra', 'helpme', 'qwertyui', 'victor', 'florida', 'dolphin', 'pookie', 'captain', 'tucker', 'blue', 'liverpool', 'theman', 'bandit', 'dolphins', 'maddog', 'packers', 'jaguar', 'lovers', 'nicholas', 'united', 'tiffany', 'maxwell', 'zzzzzz', 'nirvana', 'jeremy', 'suckit', 'stupid', 'porn', 'monica', 'elephant', 'giants', 'jackass', 'hotdog', 'rosebud', 'success', 'debbie', 'mountain', '444444', 'xxxxxxxx', 'warrior', '1q2w3e4r5t', 'q1w2e3', '123456q', 'albert', 'metallic', 'lucky', 'azerty', '7777', 'shithead', 'alex', 'bond007', 'alexis', '1111111', 'samson', '5150', 'willie', 'scorpio', 'bonnie', 'gators', 'benjamin', 'voodoo', 'driver', 'dexter', '2112', 'jason', 'calvin', 'freddy', '212121', 'creative', '12345a', 'sydney', 'rush2112', '1989', 'asdfghjk', 'red123', 'bubba', '4815162342', 'passw0rd', 'trouble', 'gunner', 'happy', 'fucking', 'gordon', 'legend', 'jessie', 'stella', 'qwert', 'eminem', 'arthur', 'apple', 'nissan', 'bullshit', 'bear', 'america', '1qazxsw2', 'nothing', 'parker', '4444', 'rebecca', 'qweqwe', 'garfield', '01012011', 'beavis', '69696969', 'jack', 'asdasd', 'december', '2222', '102030', '252525', '11223344', 'magic', 'apollo', 'skippy', '315475', 'girls', 'kitten', 'golf', 'copper', 'braves', 'shelby', 'godzilla', 'beaver', 'fred', 'tomcat', 'august', 'buddy', 'airborne', '1993', '1988', 'lifehack', 'qqqqqq', 'brooklyn', 'animal', 'platinum', 'phantom', 'online', 'xavier', 'darkness', 'blink182', 'power', 'fish', 'green', '789456123', 'voyager', 'police', 'travis', '12qwaszx', 'heaven', 'snowball', 'lover', 'abcdef', '00000', 'pakistan', '007007', 'walter', 'playboy', 'blazer', 'cricket', 'sniper', 'hooters', 'donkey', 'willow', 'loveme', 'saturn', 'therock', 'redwings', 'bigboy', 'pumpkin', 'trinity', 'williams', 'tits', 'nintendo', 'digital', 'destiny', 'topgun', 'runner', 'marvin', 'guinness', 'chance', 'bubbles', 'testing', 'fire', 'november', 'minecraft', 'asdf1234', 'lasvegas', 'sergey', 'broncos', 'cartman', 'private', 'celtic', 'birdie', 'little', 'cassie', 'babygirl', 'donald', 'beatles', '1313', 'dickhead', 'family', '12121212', 'school', 'louise', 'gabriel', 'eclipse', 'fluffy', '147258369', 'lol123', 'explorer', 'beer', 'nelson', 'flyers', 'spencer', 'scott', 'lovely', 'gibson', 'doggie', 'cherry', 'andrey', 'snickers', 'buffalo', 'pantera', 'metallica', 'member', 'carter', 'qwertyu', 'peter', 'alexande', 'steve', 'bronco', 'paradise', 'goober', '5555', 'samuel', 'montana', 'mexico', 'dreams', 'michigan', 'cock', 'carolina', 'yankee', 'friends', 'magnum', 'surfer', 'poopoo', 'maximus', 'genius', 'cool', 'vampire', 'lacrosse', 'asd123', 'aaaa', 'christin', 'kimberly', 'speedy', 'sharon', 'carmen', '111222', 'kristina', 'sammy', 'racing', 'ou812', 'sabrina', 'horses', '0987654321', 'qwerty1', 'pimpin', 'baby', 'stalker', 'enigma', '147147', 'star', 'poohbear', 'boobies', '147258', 'simple', 'bollocks', '12345q', 'marcus', 'brian', '1987', 'qweasdzxc', 'drowssap', 'hahaha', 'caroline', 'barbara', 'dave', 'viper', 'drummer', 'action', 'einstein', 'bitches', 'genesis', 'hello1', 'scotty', 'friend', 'forest', '010203', 'hotrod', 'google', 'vanessa', 'spitfire', 'badger', 'maryjane', 'friday', 'alaska', '1232323q', 'tester', 'jester', 'jake', 'champion', 'billy', '147852', 'rock', 'hawaii', 'badass', 'chevy', '420420', 'walker', 'stephen', 'eagle1', 'bill', '1986', 'october', 'gregory', 'svetlana', 'pamela', '1984', 'music', 'shorty', 'westside', 'stanley', 'diesel', 'courtney', '242424', 'kevin', 'porno', 'hitman', 'boobs', 'mark', '12345qwert', 'reddog', 'frank', 'qwe123', 'popcorn', 'patricia', 'aaaaaaaa', '1969', 'teresa', 'mozart', 'buddha', 'anderson', 'paul', 'melanie', 'abcdefg', 'security', 'lucky1', 'lizard', 'denise', '3333', 'a12345', '123789', 'ruslan', 'stargate', 'simpsons', 'scarface', 'eagle', '123456789a', 'thumper', 'olivia', 'naruto', '1234554321', 'general', 'cherokee', 'a123456', 'vincent', 'Usuckballz1', 'spooky', 'qweasd', 'cumshot', 'free', 'frankie', 'douglas', 'death', '1980', 'loveyou', 'kitty', 'kelly', 'veronica', 'suzuki', 'semperfi', 'penguin', 'mercury', 'liberty', 'spirit', 'scotland', 'natalie', 'marley', 'vikings', 'system', 'sucker', 'king', 'allison', 'marshall', '1979', '098765', 'qwerty12', 'hummer', 'adrian', '1985', 'vfhbyf', 'sandman', 'rocky', 'leslie', 'antonio', '98765432', '4321', 'softball', 'passion', 'mnbvcxz', 'bastard', 'passport', 'horney', 'rascal', 'howard', 'franklin', 'bigred', 'assman', 'alexander', 'homer', 'redrum', 'jupiter', 'claudia', '55555555', '141414', 'zaq12wsx', 'shit', 'patches', 'nigger', 'cunt', 'raider', 'infinity', 'andre', '54321', 'galore', 'college', 'russia', 'kawasaki', 'bishop', '77777777', 'vladimir', 'money1', 'freeuser', 'wildcats', 'francis', 'disney', 'budlight', 'brittany', '1994', '00000000', 'sweet', 'oksana', 'honda', 'domino', 'bulldogs', 'brutus', 'swordfis', 'norman', 'monday', 'jimmy', 'ironman', 'ford', 'fantasy', '9999', '7654321', 'PASSWORD', 'hentai', 'duncan', 'cougar', '1977', 'jeffrey', 'house', 'dancer', 'brooke', 'timothy', 'super', 'marines', 'justice', 'digger', 'connor', 'patriots', 'karina', '202020', 'molly', 'everton', 'tinker', 'alicia', 'rasdzv3', 'poop', 'pearljam', 'stinky', 'naughty', 'colorado', '123123a', 'water', 'test123', 'ncc1701d', 'motorola', 'ireland', 'asdfg', 'slut', 'matt', 'houston', 'boogie', 'zombie', 'accord', 'vision', 'bradley', 'reggie', 'kermit', 'froggy', 'ducati', 'avalon', '6666', '9379992', 'sarah', 'saints', 'logitech', 'chopper', '852456', 'simpson', 'madonna', 'juventus', 'claire', '159951', 'zachary', 'yfnfif', 'wolverin', 'warcraft', 'hello123', 'extreme', 'penis', 'peekaboo', 'fireman', 'eugene', 'brenda', '123654789', 'russell', 'panthers', 'georgia', 'smith', 'skyline', 'jesus', 'elizabet', 'spiderma', 'smooth', 'pirate', 'empire', 'bullet', '8888', 'virginia', 'valentin', 'psycho', 'predator', 'arizona', '134679', 'mitchell', 'alyssa', 'vegeta', 'titanic', 'christ', 'goblue', 'fylhtq', 'wolf', 'mmmmmm', 'kirill', 'indian', 'hiphop', 'baxter', 'awesome', 'people', 'danger', 'roland', 'mookie', '741852963', '1111111111', 'dreamer', 'bambam', 'arnold', '1981', 'skipper', 'serega', 'rolltide', 'elvis', 'changeme', 'simon', '1q2w3e', 'lovelove', 'fktrcfylh', 'denver', 'tommy', 'mine', 'loverboy', 'hobbes', 'happy1', 'alison', 'nemesis', 'chevelle', 'cardinal', 'burton', 'wanker', 'picard', '151515', 'tweety', 'michael1', '147852369', '12312', 'xxxx', 'windows', 'turkey', '456789', '1974', 'vfrcbv', 'sublime', '1975', 'galina', 'bobby', 'newport', 'manutd', 'daddy', 'american', 'alexandr', '1966', 'victory', 'rooster', 'qqq111', 'madmax', 'electric', 'bigcock', 'a1b2c3', 'wolfpack', 'spring', 'phpbb', 'lalala', 'suckme', 'spiderman', 'eric', 'darkside', 'classic', 'raptor', '123456789q', 'hendrix', '1982', 'wombat', 'avatar', 'alpha', 'zxc123', 'crazy', 'hard', 'england', 'brazil', '1978', '01011980', 'wildcat', 'polina', 'freepass']


def search_common_pws(check_string):
    for x in list_common_pws:
        if check_string in x:
            print("found common password")
            return True
    print("not found common password")
    return False


def check_dup_letters(chk):
    count = 0
    for char in chk:
        if char.isalpha():
            count = count + 1
        else:
            count = 0
        if count == 4:
            return True
    return False


def check_dup_digits(chk):
    count = 0
    for char in chk:
        if char.isdigit():
            count = count + 1
        else:
            count = 0
        if count == 4:
            return True
    return False


def four_consecutive_chars(check_string):
    if check_dup_digits(check_string) or check_dup_letters(check_string):
        return True
    return False


def valid_password(user_password):
    if len(user_password) < 8:
        return False
    if not any(char.isdigit() for char in user_password):
        return False
    if not any(char.isalpha() for char in user_password):
        return False
    if four_consecutive_chars(user_password):
        return False
    if search_common_pws(user_password):
        return False
    return True

# Designing window for registration


def register():
    global register_screen
    register_screen = Toplevel(main_screen)
    register_screen.title("Register")
    register_screen.geometry("300x250")

    global username
    global password
    global username_entry
    global password_entry
    username = StringVar()
    password = StringVar()

    Label(register_screen, text="Please enter details below", bg="blue").pack()
    Label(register_screen, text="").pack()
    username_lable = Label(register_screen, text="Username * ")
    username_lable.pack()
    username_entry = Entry(register_screen, textvariable=username)
    username_entry.pack()
    password_lable = Label(register_screen, text="Password * ")
    password_lable.pack()
    password_entry = Entry(register_screen, textvariable=password, show='*')
    password_entry.pack()
    Label(register_screen, text="").pack()
    Button(register_screen, text="Register", width=10, height=1, bg="blue", command=register_user).pack()


# Designing window for login

def login():
    global login_screen
    login_screen = Toplevel(main_screen)
    login_screen.title("Login")
    login_screen.geometry("300x250")
    Label(login_screen, text="Please enter details below to login").pack()
    Label(login_screen, text="").pack()

    global username_verify
    global password_verify

    username_verify = StringVar()
    password_verify = StringVar()

    global username_login_entry
    global password_login_entry

    Label(login_screen, text="Username * ").pack()
    username_login_entry = Entry(login_screen, textvariable=username_verify)
    username_login_entry.pack()
    Label(login_screen, text="").pack()
    Label(login_screen, text="Password * ").pack()
    password_login_entry = Entry(login_screen, textvariable=password_verify, show='*')
    password_login_entry.pack()
    Label(login_screen, text="").pack()
    Button(login_screen, text="Login", width=10, height=1, command=login_verify).pack()


# Implementing event on register button

def register_user():
    username_info = username.get()
    password_info = password.get()

    if valid_password(password_info):
        file = open("passwords.txt", "a")
        file.write("\n" + username_info + "\n")
        file.write(hash_password(password_info))
        file.close()

        username_entry.delete(0, END)
        password_entry.delete(0, END)

        Label(register_screen, text="Registration Success", fg="green", font=("calibri", 11)).pack()

    else:
        invalid_register()


# Implementing event on login button

def login_verify():
    username1 = username_verify.get()
    password1 = password_verify.get()
    username_login_entry.delete(0, END)
    password_login_entry.delete(0, END)

    file1 = open("passwords.txt", "r")
    verify = file1.read().splitlines()
    if username1 in verify and verify_password(verify[verify.index(username1) + 1], password1):

        login_sucess()

    else:
        invalid_login()


def login_sucess():
    global login_success_screen
    login_success_screen = Toplevel(login_screen)
    login_success_screen.title("Success")
    login_success_screen.geometry("150x100")
    Label(login_success_screen, text="Login Success").pack()
    Button(login_success_screen, text="OK", command=delete_login_success).pack()


# Designing popup for login invalid password

def invalid_login():
    global password_not_recog_screen
    password_not_recog_screen = Toplevel(login_screen)
    password_not_recog_screen.title("Success")
    password_not_recog_screen.geometry("150x100")
    Label(password_not_recog_screen, text="Invalid login ").pack()
    Button(password_not_recog_screen, text="OK", command=delete_password_not_recognised).pack()


# Designing popup for register invalid password

def invalid_register():
    global register_not_recog_screen
    register_not_recog_screen = Toplevel(register_screen)
    register_not_recog_screen.title("Success")
    register_not_recog_screen.geometry("150x100")
    Label(register_not_recog_screen, text="Password is weak! ").pack()
    Button(register_not_recog_screen, text="OK", command=delete_register_not_recognised).pack()


# Deleting popups

def delete_login_success():
    login_success_screen.destroy()


def delete_password_not_recognised():
    password_not_recog_screen.destroy()


def delete_register_not_recognised():
    register_not_recog_screen.destroy()

# Designing Main(first) window

def main_account_screen():
    global main_screen
    main_screen = Tk()
    main_screen.geometry("300x250")
    main_screen.title("Account Login")
    Label(text="Select Your Choice", bg="blue", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text="").pack()
    Button(text="Login", height="2", width="30", command=login).pack()
    Label(text="").pack()
    Button(text="Register", height="2", width="30", command=register).pack()

    main_screen.mainloop()


def main():
    main_account_screen()


if __name__ == "__main__":
    main()
import sys, getopt
from time import sleep
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util import Padding
from Crypto import Random

operation = 'dec'
## keystring = b'0123456789abcdef'
inputfile = 'testinput.txt'
outputfile = 'testoutput.bin'

try:
    opts, args = getopt.getopt(sys.argv[1:],'hedk:i:o:')
except getopt.GetoptError:
    print('Usage: aes_cbc.py [-e|-d] -k <keystring> -i <inputfile> -o <outputfile>')
    sys.exit(2)

for opt, arg in opts:
    if opt == '-h':
        print('Usage: aes_cbc.py [-e|-d] -k <keystring> -i <inputfile> -o <outputfile>')
        sys.exit()
    elif opt == '-e':
        operation = 'enc'    
    elif opt == '-d':
        operation = 'dec'    
    elif opt == '-k':
        keystring = arg
    elif opt == '-i':
        inputfile = arg
    elif opt == '-o':
        outputfile = arg

if (operation != 'enc') and (operation != 'dec'):
    print('Error: Operation must be -e (for encryption) or -d (for decryption).')
    sys.exit(2)
    
if len(keystring) != 16:
    print('Error: Key string must be 16 character long.')
    sys.exit(2)

if len(inputfile) == 0:
    print('Error: Name of input file is missing.')
    sys.exit(2)

if len(outputfile) == 0:
    print('Error: Name of output file is missing.')
    sys.exit(2)

# encryption
if operation == 'enc': 
    print('Encrypting...', end='')
	
    # read the content of the input file into a buffer
    ifile = open(inputfile, 'rb')
    plaintext = ifile.read()
    ifile.close()

    # generate padding and iv
    plaintext = Padding.pad(plaintext, AES.block_size)
    iv = get_random_bytes(AES.block_size)

    # create AES cipher object
    keystring = keystring.encode('utf-8')
    cipher = AES.new(keystring, AES.MODE_CBC, iv)

    # encrypt the buffer
    ciphertext = cipher.encrypt(plaintext)

    # write out the random prefix of the counter and the encrypted buffer to the output file
    print('IV:' + iv.hex())
    print('Ciphertext: ')
    print(ciphertext.hex())

    ofile = open(outputfile,'wb')
    ofile.write(iv + ciphertext)
    ofile.close()

	
# decryption
else:
    print('Decrypting...', end='')

    # read the encrypted payload from the input file
    ifile = open('testoutput.bin','rb')
    ciphertext = ifile.read()
    print(ciphertext)
    ifile.close()

    # find iv
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
	
    # create AES cipher object
    keystring = keystring.encode('utf-8')
    cipher = AES.new(keystring, AES.MODE_CBC, iv)

    # decrypt encrypted buffer
    plaintext = cipher.decrypt(ciphertext)
    plaintext = Padding.unpad(plaintext, AES.block_size)
	
    # write out the decrypted buffer into the output file
    print(plaintext.decode('utf-8'))

print('Done.')


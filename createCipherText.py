#Jason Javier
#March 24, 2017
#This script is to be used to generate a file with the ciphertext of a password 
#https://pypi.python.org/pypi/pycrypto
#pycrypto isn't compiled by default due to export restrictions. You can either compile it yourself or use easy_install to install a version compiled by someone else
#easy_install http://www.voidspace.org.uk/python/pycrypto-2.6.1/pycrypto-2.6.1.win32-py2.7.exe
#List of additional easy_install link options: http://www.voidspace.org.uk/python/pycrypto-2.6.1/

from Crypto.Cipher import AES
from subprocess import check_output
print "\nEncrypt Password for use with TanFire\n"


def main():
	key, iv = encrypt()
	decrypt(key,iv)
	print "\nSave the key   " + key + "   in config.cfg"
	print 'Rename and transfer "testmessage.txt" to the path specified in config.cfg'

def encrypt():
	print "\nFUNCTION encrypt"
	#Input cleartext password and key
	#iv needs to match the iv in TanFire.py

	#Use last 8 characters of the SN as part of the IV to limit decryption to the same box
	output=check_output("wmic bios get serialnumber", shell=False)
	SN = output.splitlines()[2].strip()
	iv = SN[-8:] + SN[-8:][::-1]

	cleartext = raw_input("Enter Cleartext Password: ")
	key = raw_input("Enter Key (MUST be either 16, 24, or 32 bytes long): ")
	
	#Pad the cleartext so it's divisible by 16
	length = len(cleartext)
	length = 16 - (len(cleartext) % 16)
	cleartext += chr(length)*length
	
	#Compute ciphertext
	obj = AES.new(key, AES.MODE_CBC, iv)
	ciphertext = obj.encrypt(cleartext)
	print "\nIV: " + str(iv)
	print "Generated ciphertext: " + ciphertext
	
	#Output ciphertest to file
	message = open('testmessage.txt', 'w')
	message.write(str(length)+'b2'+ciphertext)
	message.close()
	print 'Ciphertext has been outputted to "testmessage.txt"'
	
	return(key,iv)

	
def decrypt(key,iv):
	print "\n\nFUNCTION decrypt"
	#Input ciphertext from file
	message_input = open('testmessage.txt', 'r')
	message_input_content = message_input.read()
	message_input.close()
	List = message_input_content.split('b2')
	Length=List[0]
	encrypted=List[1]

	#Compute cleartext from ciphertext
	obj2 = AES.new(key, AES.MODE_CBC, iv)
	clearMessage = obj2.decrypt(encrypted)
	
	#Truncate clearText to original, pre-padded, length
	clearMessage = clearMessage[:-int(Length)]

	print 'Decryption verification of ciphertext in "testmessage.txt": ' + str(clearMessage)

	
if __name__ == "__main__":
	main()

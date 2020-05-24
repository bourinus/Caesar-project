# $ sage
# sage: load("example.sage")
# BruteForceAttack("tt","hh")


#
# frequence moyenne d'aparition des lettres en francais
# http://www.dcode.fr/analyse-frequences
en_alphabet  = "abcdefghijklmnopqrstuvwxyz"
ref_alphabet = "easintrluodcmpgvbfqhxjykwz"

# 
# returns true iff the caracter c is an alphabetic character
def is_alphabetic_char(c) :
	return(c.lower() in en_alphabet)

# 
# returns the numeric value corresponding to a alphabetic character
def char_to_num(c) :
	return en_alphabet.index (c.lower())
 
# 
# returns the alphabetic character corresponding to a numeric value
def num_to_char(x) :
	return en_alphabet[ x % 26 ]

# Caesar encrypt function
def CaesarEncrypt(plaintext, k) :
	ciphertext=""
	for j in xrange(len(plaintext))	:
		p = plaintext[j]
		if is_alphabetic_char(p) :
			x = ( char_to_num(p) + k ) % 26
			c = num_to_char(x)
		else : 
			c = p
		ciphertext += c	
	return ciphertext

# Caesar decrypt function
def CaesarDecrypt(ciphertext, k) :
	plaintext=""
	for j in xrange(len(ciphertext))	:
		c = ciphertext[j]
		if is_alphabetic_char(c) :
			x = ( char_to_num(c) - k ) % 26
			p = num_to_char(x)
		else : 
			p = c
		plaintext += p
	return plaintext
	




#
# Breaking Caesar cipher via brute force
#

# look for optional parameter 'keyword'
def BruteForceAttack(ciphertext, keyword=None) :
	for k in xrange(26) :
		plaintext = CaesarDecrypt(k, ciphertext)
		if (None==keyword) or (keyword in plaintext) :
			print "key", k, "decryption", plaintext
	return

#
# Mono Statiscal Analysis
def Mono_Statiscal_Analysis(text) :
	# utiliser des tuple !! 2array
	list=[]
	for k in xrange(26) :
		#pour chaque lettre donne , compte l'occurence
		# stocke l'ocurence et la ltter associe
		toto = num_to_char(k)
		list += [[text.count(toto),toto]]	
	from operator import itemgetter
	list.sort(key=itemgetter(0), reverse=1)
 	#print char_to_num(list[25][1])
	return	list

#
# Breaking  Caesar cipher via statiscal analysis  -1by1-
def Frequential_Attack(ciphertext) :
	data = Mono_Statiscal_Analysis(ciphertext)
	print
	print data
	print
	# searching for 'e' = ref_alphabet[0]
	for k in xrange(26) :
		cle_probable = ( char_to_num(data[k][1])-char_to_num(ref_alphabet[0])) % 26
		print "hypothese", k+1 ,":", ref_alphabet[0]," clair_=_chiffre", data[k][1], "=> cle = ", cle_probable
		print CaesarDecrypt(ciphertext, cle_probable)
		print
	petersen_spring = Graph(':I`ES@obGkqegW~')
	petersen_spring.show() # long time
	petersen_database = graphs.PetersenGraph()
	petersen_database.show() # long time
	return











# Afine encrypt function
def AfineEncrypt(plaintext, a,b) :
	ciphertext=""
	for j in xrange(len(plaintext))	:
		p = plaintext[j]
		if is_alphabetic_char(p) :
			x = ( a*char_to_num(p) + b ) % 26
			c = num_to_char(x)
		else : 
			c = p
		ciphertext += c	
	return ciphertext

# Afine decrypt function
def AfineDecrypt(ciphertext, a, b) :
	plaintext=""
	for j in xrange(len(ciphertext))	:
		c = ciphertext[j]
		if is_alphabetic_char(c) :
			x = 1/a*( char_to_num(c) - b ) % 26
			p = num_to_char(x)
		else : 
			p = c
		plaintext += p
	return plaintext


def main():
	text="vcfgrwqwfsbhfsntowbsobgfsbhfsnqvsnjcigsghqsoixcifrviwtshseicwbsgojsnjcigdogeisjcigoihfsgofhwgobgjcigbsrsjsnqwfqizsfrobgzsgfisgzsgxcifgcijfopzsgeiojsqzsggwubsgrsjchfsdfctsggwcbdofzseiszsghhcbashwsf"
	print Frequential_Attack(text)
	pass

main()
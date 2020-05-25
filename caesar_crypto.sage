# -*- coding: utf-8 -*-
#
## Caesar cypher implementation
#  	- cypher/decypher
#   - cryptanalysis via frequential analysis and language soundness 
#
## Execution example in terminal
# $ sage
# sage: load("example.sage")
# BruteForceAttack("tt","hh")
#
## frequence moyenne d'aparition des lettres en francais
# http://www.dcode.fr/analyse-frequences

import unicodedata

en_alphabet  = "abcdefghijklmnopqrstuvwxyz"
ref_alphabet = "easintrluodcmpgvbfqhxjykwz"

# 
# returns text: in lower case, without space and accent
def normalize(c) :
	s=c.lower() 		# lowec case
	s.replace(" ", "")  # space
	s = unicode(s,'utf-8')
	s = unicodedata.normalize('NFKD', s).encode('ascii', 'ignore') 
	return s

#
# returns lower form of input character
def is_alphabetic_char(c) :
	return c.lower() in en_alphabet
  
# 
# returns the numeric value corresponding to an alphabetic character
def char_to_num(c) :
	return en_alphabet.index (c.lower())
 
# 
# returns the alphabetic character corresponding to a numeric value
def num_to_char(x) :
	return en_alphabet[ x % 26 ]

#
# realises the Caesar cipher encrypt function
def CaesarEncrypt(plaintext, k) :
	ciphertext=""
	plaintext=normalize(plaintext)
	print "normalized plaintext",		plaintext
	for j in xrange(len(plaintext))	:
		p = plaintext[j]
		if is_alphabetic_char(p) :
			ciphered_num = ( char_to_num(p) + k ) % 26
			ciphered_letter = num_to_char(ciphered_num)
		else : 
			ciphered_letter = p
		ciphertext += ciphered_letter	
	return ciphertext

#
# realises the Caesar cipher decrypt function
# ( useless as crypt(-k)=decrypt(k) )
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
# -looking for optional parameter 'keyword'-
def BruteForceAttack(ciphertext, keyword=None) :
	for k in xrange(26) :
		plaintext = CaesarDecrypt(k, ciphertext)
		if (None==keyword) or (keyword in plaintext) :
			print "key", k, "decryption", plaintext
	return

#
# return alphabet ordered with frequency in text
def Mono_Statiscal_Analysis(text) :
	# utiliser des tuple !! 2array
	q=len(text)
	list=[]
	for k in xrange(26) :
		# produce alphabet with freqency in text
		x = num_to_char(k)
		y = N(100*text.count(x)/q,digits=3)
		list += [[y,x]]	
	from operator import itemgetter
	# order the list to get most used first
	list.sort(key=itemgetter(0), reverse=1)
	#print list
 	liste=[]
 	# fancy return list without probability
 	for k in xrange(26) :
 		liste += [list[k][1]]
	return liste

# Breaking  Caesar cipher via statiscal analysis  -1by1-
def Caesar_Frequential_Attack(ciphertext) :
	data = Mono_Statiscal_Analysis(ciphertext)
	print data
	# searching for 'e' = ref_alphabet[0]
	for k in range(0,26) :
		# hypothesis e ---> data[k]
		probable_key = ( char_to_num(data[k])-char_to_num(ref_alphabet[0])) % 26
		print "hypothese", k+1 ,":", ref_alphabet[0]," clair_=_chiffre", data[k], "=> cle = ", probable_key
		print probable_key, "decryption attempted :", 
		# testing if hypothesis seems french
		string = CaesarDecrypt(ciphertext, probable_key)
		dico(string,probable_key)
		if dico(string,probable_key)==true:
			return

# return true if french
def dico(test_string, probable_key):
	# counting number of word of dico in test_string
	f = open("dico.txt","r")
	k=0 			
	for line in f:
		if str(line.rstrip('\n')) in str(test_string):
			#print "I found the word :", str(line.rstrip('\n'))
			k=k+1
	# Percentage of meaningfull word	
	r= N(100*k/len(str(test_string)),digits=3)
	# matching case
	print "words:", k, ", ratio", r
	if k>10 and r>10:                                  
		print ""
		print  "	!!!!	Found	!!!!		"
		print "a total of ", k, "words and", r, "of quotient" 
		print "probable key:", probable_key
		print ""
		print "probable cleartext:"
		print test_string
		return true
	else :
		return false

#
# defining main as what you want
def main():
	text="Situe en plein coeur dun pole dentreprises lEPSI ouvre ses portes pour la première fois en septembre deux mille seize au sein du Brest Open Campus Sur un espace unique de trois milles metres carres sentremelent culture enseignement et monde de lentreprise A mi chemin entre le centre ville de Brest et laeroport le campus est très accessible en voiture comme en transport en commun Tramway a moins de cent mètres Des atouts qui font la difference trois milles metres carres dedies au partage des connaissances des idees et des experiences  Un concept original pour favoriser le partage entre etudiants professeurs entreprises et institutions culturelles artistiques et sportives Un environnement dynamique et innovant disposant dun espace de coworking de laboratoires Business Lab Tech Lab et Studio Lab de ressources numeriques et de materiels a la disposition des etudiants Une cafeteria numerique denviron deux cents metres carres qui accueillera un concept inedit ideation en cours Une mediathèque ergonomique propice au travail et au partage Un pôle denseignement superieur qui regroupe trois ecoles leaders dans leur domaine lEPSI ecole dingenierie informatique lIFAG ecole de management et SUPDE COM ecole de communication"
	cipher=CaesarEncrypt(text,22)
	print "ciphered :", cipher
	Caesar_Frequential_Attack(cipher)
	pass

#
# Executing main
main()

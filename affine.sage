# -*- coding: utf-8 -*-
# $ sage
# sage: load("example.sage")
# BruteForceAttack("tt","hh")


#
# frequence moyenne d'aparition des lettres en francais
# http://www.dcode.fr/analyse-frequences
en_alphabet  = "abcdefghijklmnopqrstuvwxyz"
ref_alphabet = "easintrluodcmpgvbfqhxjykwz"

import unicodedata
# 
# returns text: in lower case, without space and accent
def normalize(c) :
	s=c.lower() 		# lowec case
	s.replace(" ", "")  # space
	s = unicode(s,'utf-8')
	s = unicodedata.normalize('NFKD', s).encode('ascii', 'ignore') 
	return s

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

# realise Caesar cipher encrypt function
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

# realise Caesar cipher decrypt function
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

# Affine cipher  encrypt function
def AffineEncrypt(plaintext, a,b) :
	if gcd(a,26) != 1 : # test bijection
		return "non reversible encryption"
	else : 
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


# Affine cipher decrypt function
def AffineDecrypt(ciphertext, a, b) :
	if gcd(a,26) != 1 : # test bijection
		return "impossible"
	else : 
		plaintext=""
		for j in xrange(len(ciphertext))	:
			c = ciphertext[j]
			if is_alphabetic_char(c) :
				x = inverse_mod(a, 26)*( char_to_num(c) - b ) % 26
				p = num_to_char(x)
			else : 
				p = c
			plaintext += p
		return plaintext

# solving particular system mod 26
# a(l0-l1)=x0-x1 % 26
def system_solve(l0,x0,l1,x1) :
	if l0==l1 :
		return "impossible"
	k=0
	li=[]
	if mod(x0-x1,2)!=1 :
		while len(li)<2:
			tmp=(x0-x1+k*26)/(l0-l1) 
			k+=1
			if tmp in ZZ:
				li+=[[int(tmp %26),int((x0-tmp*l0) %26)]]
	return li

# return true if french
def dico(test_string, probable_key):
	# counting number of word of dico in test_string
	f = open("dico.txt","r")
	k=0 			
	for line in f:
		if str(line.rstrip('\n')) in str(test_string):
			#print "I found the word :", str(line.rstrip('\n'))
			k=k+1
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

def Affine_Frequential_Attack(ciphertext) :
	data = Mono_Statiscal_Analysis(ciphertext)
	print
	print "data = ", data
	print "stat = ", ref_alphabet
	print
	cpt=0
	for k in range(0,26):
		for l in range(0,26): 
			# round
			print ">> cpt",cpt,
			print "k,l=",k,l,":		",ref_alphabet[0],ref_alphabet[1],"-->",data[k],data[l]
			# hypothesis
			print "   {",char_to_num(ref_alphabet[0]), "a + b =",char_to_num(data[k])
			print "   {",char_to_num(ref_alphabet[1]), "a + b =",char_to_num(data[l]),
			cpt += 1
			# all (a,b) given by this hypothesis
			result = system_solve(
				char_to_num(ref_alphabet[0]),char_to_num(data[k]),
				char_to_num(ref_alphabet[1]),char_to_num(data[l])) 
			print "	",result
			# test all of them
			for m in range(0,len(result)):
				tmp=result[m]
				if gcd(tmp[0],26)!=1: 	# canceling non bijection
					print tmp, "impossible candidate"
				else :					# is french ?
					print tmp, "decryption attempted :", 
					string = AffineDecrypt(ciphertext, tmp[0], tmp[1])
					if dico(string,tmp)==true:
						return

def main():
	text="millions Belgique moisleurstauxannéestempsgroupeainsitoujourssociétédepuistoussoitfautBruxellesfoisquelquesseraentreprisescontrefrancsnanouscettedernierétaitestchezmondealorssousactionautresilsrestetroisnonnotredoitnouveaumilliardsavantexemplecomptebelgepremiernouvelleEllelontermeavaitproduitscelaautresfinniveaubénéficetoutetravailpartietrophaussesecteurpartbeaucoupJevaleurcroissancerapportUSDaujourdhuiannéebaseBourselorsverssouventvieentrepriseautrepeuventbonsurtouttoutesnombrefondspointgrandejourvaavoirnosquelqueplacegrandpersonnesplusieurscertainsdaffairespermetpolitiquecetchaquechiffrepourraitdevraitproduitlannéeparrienmieuxceluiqualitéFranceilscessagitventejamaisproductionactionbaisseavecrésultatsdesvotrerisquedébutbanqueanvoiravonsunquellesmomentquestionpouvoirtitredoutelongpetitdailleursnotammentFBdroitelleheurescependantserviceEtats-Unisilsactionjourscelledemandebelgesceuxservicesbonneserontéconomiqueraisoncarsituationdepuisentreprisenouvellespossibletoutefoistantnouveauxselon"
	cipher=CaesarEncrypt(text,22)
	print "ciphered :", cipher
	Caesar_Frequential_Attack(cipher)

	#print text
	#Affine_Frequential_Attack(text) 
	pass
	#print AffineDecrypt(text,11,1)
	

main()
#
## -*- coding: utf-8 -*-
# 
#import unicodedata
#
#""" Normalise (normalize) unicode data in Python to remove umlauts, accents etc. """
#
#data = 'naïve café'
#s=data.lower()
#print data, "ddd"
#s1 = unicode(s,'utf-8')
#s2 = unicodedata.normalize('NFKD', s1).encode('ascii', 'ignore') 
##	t1=unidecode(s)
##	t=t1.encode("ascii")
##	return t.lower() in en_alphabet
#print "kjhlkjhlkjhlkjh", s in en_alphabet, s2
## prints "naive cafe"
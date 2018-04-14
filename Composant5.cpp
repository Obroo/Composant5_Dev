// Composant5.cpp : Defines the exported functions for the DLL application
#include <iostream>
#include "Composant5.h"
#include "Signature.h"
#include "Bloc.h"
#include "Hacheur.h"
#include "FileInterface.h"
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

#define HASH_SIZE 64
CComposant5::CComposant5()
{
	std::cout << "constructeur" << std::endl;
}

using namespace std;

char* chars_to_string(char* source) {
	std::string str(source);
	char * cstr = new char[str.length() + 1];
	std::strcpy(cstr, str.c_str());
	return cstr;
}


bool CComposant5::verify_transaction_input(TXI* txi) {
	FileInterface f("");
	Bloc* b_input = &(f.findByIndex(txi->nBloc));
	return (Signature::validateSignature(chars_to_string((char*)b_input->tx1.UTXOs[0].hash), chars_to_string((char*)b_input->tx1.UTXOs[0].dest),
		chars_to_string((char*)txi->signature)));
}

bool CComposant5::verify_transaction(TX* tx) {
	std::vector<TXI> v = tx->TXIs;
	for (std::size_t i = 0; i<v.size(); ++i) {
		if (!verify_transaction_input(&v[i]))
			return false;
	}
	return true;
}

bool CComposant5::verify_bloc(Bloc b, std::string hash_bloc_precedant, int nonce) {
	std::string str(b.previous_hash);
	char * cstr = new char[str.length() + 1];
	std::strcpy(cstr, str.c_str());
	return (
		verify_hash(&b, b.hash) &&
		strcmp(cstr, hash_bloc_precedant.c_str()) &&
		verify_transaction(&(b.tx1)));
}

bool CComposant5::verify_hash(Bloc* b, std::string hash_bloc) {
	for (int i = 0; i<HASH_SIZE; i++)
		b->hash[0];
	Hacheur h;
	return h.verifier_hachage(b->ToString(), hash_bloc);
}


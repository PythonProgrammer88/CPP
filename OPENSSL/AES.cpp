#include <iostream>

using namespace std;

#include <string>
#include <openssl/evp.h>
#include <openssl/objects.h>

static const unsigned char DCPKey[] = {0xC2,0x3B,0x73,0xCC,0xF0,0x2E,0x4D,0xBA,
										 0xAF,0xDE,0x73,0x54,0x90,0xCD,0xAB,0xEF,
										 0xA1,0xC8,0x02,0x3A,0xFC,0x40,0xA8,0xB4,
										 0xB4,0x70,0x0A,0x3E,0xCA,0xA7,0x04,0xE3};

string AES_Decrypt(string ENCstr)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	int ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, DCPKey, NULL);
    unsigned char* result = new unsigned char[ENCstr.length()]; // Make a big enough space
    int *len1 = new int();;
    ret = EVP_DecryptUpdate(ctx, result, len1, (const unsigned char*)ENCstr.data(), ENCstr.length());
    int *len2 = new int();
    ret = EVP_DecryptFinal_ex(ctx, result+ *len1, len2); 
    ret = EVP_CIPHER_CTX_cleanup(ctx);
    string res((char*)result, *len1+ *len2);
    delete[] result;
	delete len1;
	delete len2;
	EVP_CIPHER_CTX_free(ctx);

    return res;
}

string AES_Encrypt(const std::string source)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

    int ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, DCPKey, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
    unsigned char* result = new unsigned char[source.length() + 64]; // Make a big enough space
    int *len1 = new int();
    ret = EVP_EncryptUpdate(ctx, result, len1, (const unsigned char*)source.data(), source.length());
    int *len2 = new int();
    ret = EVP_EncryptFinal_ex(ctx, result+*len1, len2); 
    ret = EVP_CIPHER_CTX_cleanup(ctx);
    std::string res((char*)result, *len1 + *len2);
    delete[] result;
	delete len1;
	delete len2;
	EVP_CIPHER_CTX_free(ctx);
    return res;
}

int main(int argc, char* argv[])
{
	cout << "AES Encryption Decryption in progress.. Keep Waiting" << endl;



	char buf[1024*100];
   	FILE* ifp = fopen("input.txt", "rb");
 	int bytes = fread(buf, 1, 1024*100, ifp);
 	fclose(ifp);
	std::string source(buf, bytes); // binary data

	string Encrypted_Data = AES_Encrypt (source);
	//cout << "Encrypted Data: " << Encrypted_Data << endl;

	FILE* efp =  fopen("encrypted.txt", "wb");
 	fwrite(Encrypted_Data.data(), 1, Encrypted_Data.length(), efp);
	fclose(efp);

	string Decrypted_Data = AES_Decrypt (Encrypted_Data);

	FILE* dfp =  fopen("output.txt", "wb");
 	fwrite(Decrypted_Data.data(), 1, Decrypted_Data.length(), dfp);
	fclose(dfp);


	return 0;
}

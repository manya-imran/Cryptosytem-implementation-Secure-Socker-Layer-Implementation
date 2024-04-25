#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <bits/stdc++.h>
#include <algorithm>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
using namespace std;

string ToString(char a[], int len)
{
    string str = a;
    return str;
}

char AESkey[33];
//-----AES-----
int Encryption(unsigned char*text,int text_len,unsigned char* key,unsigned char* cipher)
{
	int cipher_len=0;
	int len=0;
	
	EVP_CIPHER_CTX *ctx= EVP_CIPHER_CTX_new();
	
	if(!ctx)
	{
		perror("EVP_CIPHER_CTX_new() failed");
		exit(-1);
	}
	
	if(!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(),NULL,key,NULL))
	{
		perror("EVP_EncryptInit_ex() failed");
		exit(-1);
	}
	if(!EVP_EncryptUpdate(ctx,cipher,&len,text,text_len))
	{
		perror("EVP_EncryptUpdate() failed");
		exit(-1);
	}
	
	cipher_len+=len;
	
	if(!EVP_EncryptFinal_ex(ctx,cipher+len,&len))
	{
		perror("EVP_EncryptFinal_ex() failed");
		exit(-1);
	}
	
	cipher_len+=len;
	
	EVP_CIPHER_CTX_free(ctx);
	return cipher_len;
	
}

int Decryption(unsigned char* cipher, int cipher_len, unsigned char* key, unsigned char* text)
{
	int text_len=0;
	int len=0;
	
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if(!ctx)
	{
		perror("EVP_CIPHER_CTX_new() failed");
		exit(-1);
	}
	
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(),NULL, key,NULL))
	{
		perror("EVP_DecryptInit_ex() failed");
		exit(-1);
	}
	if(!EVP_DecryptUpdate(ctx,text,&len,cipher,cipher_len))
	{
		perror("EVP_DecryptUpdate() failed");
		exit(-1);
	}
	
	text_len+=len;
	
	if(!EVP_DecryptFinal_ex(ctx,text+len,&len))
	{
		perror("EVP_DecryptFinal_ex() failed");
		exit(-1);
	}
	
	text_len+=len;
	
	EVP_CIPHER_CTX_free(ctx);
	return text_len;
}
string AESKey()
{
    string str;
    ifstream in;
    int i=0;
    in.open("peer1AES.txt");
    while(getline(in,str)&&i<1)
    {
    	//cout<<i<<": "<<str[i]<<endl;
    	i++;
    }
    //openssl enc -aes-128-cbc -k secret1 -P -md sha256 -iter 16 >> peer2AES.txt
    str.erase(0, 4);
    return str;// tmp_s;
    
}
int findMax(int ax,int bx)
{
	if(ax>bx)
	{
		return ax;
	}
	else
	{
		return bx;
	}
}

string findComm(char a[],char b[])
{
	cout<<"1"<<endl;
	int n1=strlen(a);
	int n2=strlen(b);
	int max=findMax(n1,n2);
	int ax=0,bx=0;
	for(int i=0;i<n1;i++)
	{
		if(a[i]==',')
		{
			ax++;
		}	
	}
	ax++;
	
	for(int i=0;i<n2;i++)
	{
		if(b[i]==',')
		{
			bx++;
		}	
	}
	bx++;
	int M=findMax(ax,bx);
	string A[ax],B[bx];
	int j=0;
	for(int i=0;i<n1;i++)
	{
		A[j]+=a[i];
		if(a[i]==',')
		{
			j++;
		}	
	}
	j=0;
	for(int i=0;i<n2;i++)
	{
		B[j]+=b[i];
		if(b[i]==',')
		{
			j++;
		}
	}
	for(int i=0;i<ax;i++)
	{
		cout<<A[i]<<endl;
	}
	for(int i=0;i<bx;i++)
	{
		cout<<B[i]<<endl;
	}
	string resultant;
	for(int i=0;i<ax;i++)
	{
		string temp=A[i];
		for(int j=0;j<bx;j++)
		{
			if(B[j]==temp)
			{
				resultant+=temp;
				//resultant+=',';
			}
		}
	}
//	cout<<resultant<<endl;
	return resultant;

}
//AES ENCRYPT
unsigned char * encrypt(char array[],char AESkey[])
{
	int n=strlen(array);
	
	unsigned char *text_sending=new unsigned char [n];
	text_sending=(unsigned char*)array;
	int length = strlen((const char*)text_sending);
	unsigned char *cipher_text= new unsigned char[16];
	int length_generated=Encryption(text_sending, length, (unsigned char*)AESkey, cipher_text);
	for(int i=0;i<length_generated;i++)
	{
		printf("%02x",cipher_text[i]);//print in unsigned hexa 
	}
	cout<<endl;
//	cout<<"hh"<<length_generated<<endl;
	return cipher_text;
}
//AES DECRYPT
char* decrypt(char p[],char AESkey[])
{
	unsigned char decrypted[64];
//	cout<<strlen(AESkey)<<endl;
	
	int pL=strlen(p);
	unsigned char t[16];
	for(int i=0;i<16;i++)
	{
		t[i]=(unsigned char)p[i];
//		printf("%x",t[i]);
	}
	//cout<<endl;
	
	int dec_len = Decryption(t, 16,(unsigned char*)AESkey, decrypted);
	char *array=new char[dec_len];
	
	for(int i=0;i<dec_len;i++)
	{
		cout<<(const char)decrypted[i];//<<" ";
		array[i]=(const char)decrypted[i];
	}
	cout<<endl;
	array[dec_len]='\0';
	return array;
	
}

//SHA 256
string sha256(const string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    
    return ss.str();
}


//INTEGRITY
bool checkIntegrity(char a[],char b[])
{
	int n1=strlen(a);
	int n2=strlen(b);
	string str1,str2;
	str1=sha256(a);
	str2=ToString(b,n2);
	//cout<<str1<<"\n"<<str2<<"\n";
	if(str1==str2)
	{
		return true;
	}
	else
	{
		return false;
	}
}

//HMAC
string hmacHex(string key, string msg)
{

    unsigned char hash[32];

    HMAC_CTX *hmac=HMAC_CTX_new();
    HMAC_Init_ex(hmac, &key[0], key.length(), EVP_sha256(), NULL);
    HMAC_Update(hmac, (unsigned char*)&msg[0], msg.length());
    unsigned int len = 32;
    HMAC_Final(hmac, hash, &len);
    HMAC_CTX_free(hmac);

    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < len; i++)
    {   
        ss << hex << setw(2)  << (unsigned int)hash[i];
    }

    return (ss.str());
}
string hmacKey()
{
	//echo -n "secret-message" | openssl dgst -sha256 -hmac "manya-imran" -binary | openssl enc -base64 -A >>hmacKey.txt
	ifstream in;
	in.open("hmacKey.txt");
	string str;
	getline(in,str);
	cout<<str<<endl;
	in.close();
	return str;
}
bool checkAuthenticity(char a[],char b[])
{
	int n1=strlen(a);
	int n2=strlen(b);
	string str1,str2;
	string key=hmacKey();
	str1=hmacHex(key,a);
	str2=ToString(b,n2);
	cout<<str1<<"\n"<<str2<<"\n";
	if(str1==str2)
	{
		return true;
	}
	else
	{
		return false;
	}
}

//RSA

//RSA
void RSA_Test(unsigned char plain_text_sender[])

{
    RSA* key;
    unsigned char cipher_text[256];
    /*unsigned char plain_text_sender[] = "this is highly confidential shit we ve got here repaet after thy queen bow before her you pussy i aint even testing u" ;//RSA Test 1";
    //117 max chars*/

    cout<<strlen((const char *)plain_text_sender)<<endl; 				//117 max chars
    unsigned char plain_text_receiver[256];
    unsigned int num;
    BIO *bp_public = NULL, *bp_private = NULL;
    BIGNUM* bn;
    bn = BN_new();
    BN_set_word(bn, 3);

    key = RSA_new();
    int res = RSA_generate_key_ex(key, 1024, bn, NULL);

	if(res != 1)
	{
		goto free_all;
	}
	bp_public = BIO_new_file("public.txt", "w+");
	res = PEM_write_bio_RSAPublicKey(bp_public, key);
	if(res != 1)
	{
		goto free_all;
	}
	bp_private = BIO_new_file("private.txt", "w+");
	res = PEM_write_bio_RSAPrivateKey(bp_private, key, NULL, NULL, 0, NULL, NULL);


    	if (RSA_check_key(key) == 1)
        	printf("validate key\n");

 

	printf("plaintext=%s\n", plain_text_sender);
        num = RSA_public_encrypt(sizeof((const char *)plain_text_sender) - 1, plain_text_sender, cipher_text, key, RSA_PKCS1_PADDING);

    	for (int i = 0; i < 256; i++)

        	printf("%x", cipher_text[i]);

    	printf("\n");

 
	cout<<key<<endl;
    	num = RSA_private_decrypt(num, cipher_text, plain_text_receiver, key, RSA_PKCS1_PADDING);

    	plain_text_receiver[num] = '\0';

        printf("plaintext=%s\n", plain_text_receiver);	
	free_all:

	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(key);
	BN_free(bn);

}

int main()
{
	srand((unsigned)time(NULL) * getpid());

	string x=AESKey();
	strcpy(AESkey,x.c_str());
	
	char buf[500] = "";
	char p_message[256] = "";
	// create the socket
	int sock;
	sock = socket(AF_INET, SOCK_STREAM, 0);

	//setup an address
	struct sockaddr_in server_address;
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = INADDR_ANY;
	server_address.sin_port = htons(3001);

	connect(sock, (struct sockaddr *)&server_address, sizeof(server_address));

	//for (int i = 0; i < 5; i++)
	//{
	char Other_CS[500]="";
	char Decision[500]="";
	char Other_AESkey[33]="";
	send(sock, "p",1, 0);//activation
	
	//CIPHER-SUITE EXCHANGE
	recv(sock,&Other_CS,sizeof(Other_CS),0);
	puts(Other_CS);	
	char cipher_suite[]={"AES,SHA256,HMAC"};
	send(sock,cipher_suite,sizeof(cipher_suite),0);
	string common=findComm(cipher_suite,Other_CS);
	cout<<common<<endl;
	int n=common.size();
	char Comm[n+1];
	strcpy(Comm, common.c_str());
	//cout<<Comm<<endl;	
	recv(sock,&Decision,sizeof(Decision),0);
	cout<<"Descision: ";//<<endl;
	puts(Decision);
	send(sock,Comm,sizeof(Comm),0);
	
	//if-------------------------------------------
	
	cout<<"My AES key: ";
	puts(AESkey);
	cout<<"HMAC key: ";
	string hmac_key=hmacKey();
	cout<<hmac_key<<endl;
	
	//PHASE 2- EXCHANGE OF CREDENTIALS
	recv(sock,&Other_AESkey,sizeof(Other_AESkey), 0);
	cout<<"Other Peer's AES key: ";//<<endl;
	puts(Other_AESkey);
	send(sock,AESkey,sizeof(AESkey),0);
		
	unsigned char *b;//=new char [16];
	unsigned char y[16];
	//PHASE 3 SESSION
	while(1)
	{
		cout<<"\nEnter the peer1 Message : ";
		cin.getline(p_message,256);
		if(!strcmp(p_message,"Q"))
		{
			break;
		}
		cout<<"Encrypted: ";//<<encrypt(client_message,AESkey)<<endl;
		//unsigned char *e;//=new char[16];
		unsigned char *e=encrypt(p_message,AESkey);
		//cout<<strlen((ce)<<endl;
		unsigned char t[16];
		for(int i=0;i<16;i++)
		{
			t[i]=(unsigned char)e[i];
//			printf("%x",t[i]);
		}
		send(sock, t, sizeof(t), 0);
		
		//MSG RECV
		recv(sock, &y, sizeof(y), 0);
//		cout<<strlen((const char*)y)<<endl;
		unsigned char*d=y;
		cout<<"Recieved and decrypted: ";
		char *dec=decrypt((char *)d,Other_AESkey);
		cout<<dec<<endl;
	
		//SHA 256
		int pLen=strlen(p_message);
		string toBHashed=ToString(p_message,pLen);
		cout<<"string: "<<toBHashed<<endl;
		string hash=sha256(p_message);
		cout<<"hash: "<<hash<<endl;
		int hashSize=hash.size();
		char hashSent[hashSize+1];
		strcpy(hashSent, hash.c_str());
		cout<<"hash Sent: "<<hashSent<<endl;
		send(sock, hashSent, sizeof(hashSent), 0);
		
		
		//HASH INTEGRITY CHECK
		char hashRecvd[200]="";
		recv(sock, &hashRecvd, sizeof(hashRecvd), 0);
		cout<<"Hash Recieved: ";
		puts(hashRecvd);
		if(checkIntegrity(dec,hashRecvd))
		{
			cout<<"Integrity maintained!"<<endl;
		}
		else
		{
			cout<<"Its been tampered. Red flag!"<<endl;
		}
		
		//sleep(1);
		
		
		
		//HMAC INTEGRITY CHECK
		char hmacRecvd[200]="";
		recv(sock, &hmacRecvd, sizeof(hmacRecvd), 0);
		cout<<"Hmac Recieved: ";
		puts(hmacRecvd);
		if(checkAuthenticity(dec,hmacRecvd))
		{
			cout<<"Authentic!"<<endl;
		}
		else
		{
			cout<<"Not Authentic. Red flag!"<<endl;
		}
		
		//HMAC
		string hmac=hmacHex(hmac_key,p_message);
		cout<<"hmac: "<<hmac<<endl;
		int hmacSize=hmac.size();
		char hmacSent[hmacSize+1];
		strcpy(hmacSent, hmac.c_str());
		cout<<"hmac Sent: "<<hmacSent<<endl;
		send(sock, hmacSent, sizeof(hmacSent), 0);
		
		
		
		
	} 
	//PHASE 4 TERMINATION
	close(sock);

	return 0;
}

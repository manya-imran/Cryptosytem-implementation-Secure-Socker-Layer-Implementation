#include <openssl/hmac.h>
#include <string.h>
#include <iostream>
#include <stdio.h>
#include<openssl/evp.h>
#include<openssl/conf.h>
#include <algorithm>
#include<unistd.h>
#include <string>
#include<fstream>
#include<iomanip>
using namespace std;

int main()
{
	string str;
    ifstream in;
    int i=0;
    in.open("peer1AES.txt");
    while(getline(in,str)&&i<1)
    {
    	cout<<i<<": "<<str<<endl;
    	i++;
    }
    //openssl enc -aes-128-cbc -k secret1 -P -md sha256 -iter 16 >> peer2AES.txt
    cout<<"thru ssl: "<<str<<endl;
    in.close();
    
}

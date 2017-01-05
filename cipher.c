/*
A design of Block Cipher 
Author: chaonin 
Design: zzhitter
Date  : 2008/12/20
*/
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#define ROUNDS 8  //key schedule is based on ROUNDS, if ROUNDS changes the key schedule has to be changed!
#define A 127 
#define B 225

int Ex_Euclid(int r,int p)
{
	int R,TR,q,s,ts,T;
	R=p;TR=r;s=0;ts=1;
	
	while(TR!=0)
	{
        printf("R=%d, TR=%d \n",R,TR);
		q=R/TR;
		
		T=R%TR; 
		R=TR;TR=T;
		
		T=s-q*ts;
		s=ts;ts=T;
        printf("T=%d, s=%d, ts=%d \n",T,s,ts);
        printf("R=%d, TR=%d \n\n",R,TR);
	}
	if(s<0)s+=p;
	return s;
}
void reversesubkey(unsigned char *subkey)
{
	int i;
	unsigned char temp[2];
	for(i=1;i<=4;i++)
	{
		temp[0]=subkey[2*i-2];temp[1]=subkey[2*i-1];
		subkey[2*i-2]=subkey[16-2*i];subkey[2*i-1]=subkey[16-2*i+1];
		subkey[16-2*i]=temp[0];subkey[16-2*i+1]=temp[1];
	}
}
unsigned char* key_schedule(unsigned char key[4],unsigned char subkey[2],char tag)
{
    /*make subkey: shift the 32bits key to subkey Ki..
            bit 
            33222222 22221111 111111          
            10987654 32109876 54321098 7654321 
      key = XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXX
            -------- -------
               |        |
               V        V
                   K1
                   --
                ---- ------- ----
                  |           |
                  V           V
                      K2
                      --
                        ... 

      K1: key[0]-key[15] (bit16~bit31 from right to left)
      K2: key[4]-key[19]
      K3: key[8]-key[23]
      K4: key[12]-key[27]
      K5: key[16]-key[31]
      K6: key[20]-key[31] and key[0]-key[3]
      K7: key[24]-key[23] and key[4]-key[7]
      K8: key[28]-key[23] and key[8]-key[11]
    */
	int i;
	unsigned char tempK[4],KHigh,KLow;
	if(tag=='e')
	{
		for(i=0;i<4;i++)
				tempK[i]=key[i];
		for(i=1;i<=ROUNDS;i++)
		{
			if((4*(i-1))%8==0)
			{
				subkey[2*i-2]=tempK[((4*i)/8)%4];
				subkey[2*i-1]=tempK[((4*i)/8+1)%4];
			}
			else
			{
				KHigh=tempK[(4*(i-1)/8)%4];KHigh=KHigh << 4;
				KLow=tempK[(4*(i-1)/8+1)%4];KLow=KLow >> 4;
				subkey[2*i-2]=KHigh^KLow;
				KHigh=tempK[(4*(i-1)/8+1)%4];KHigh=KHigh << 4;
				KLow=tempK[(4*(i-1)/8+2)%4];KLow=KLow >> 4;
				subkey[2*i-1]=KHigh^KLow;
			}
		}
	}
	else
	{
		for(i=0;i<4;i++)
				tempK[i]=key[i];
		for(i=1;i<=ROUNDS;i++)
		{
			if((4*(i-1))%8==0)
			{
				subkey[2*i-2]=tempK[((4*i)/8)%4];
				subkey[2*i-1]=tempK[((4*i)/8+1)%4];
			}
			else
			{
				KHigh=tempK[(4*(i-1)/8)%4];KHigh=KHigh << 4;
				KLow=tempK[(4*(i-1)/8+1)%4];KLow=KLow >> 4;
				subkey[2*i-2]=KHigh^KLow;
				KHigh=tempK[(4*(i-1)/8+1)%4];KHigh=KHigh << 4;
				KLow=tempK[(4*(i-1)/8+2)%4];KLow=KLow >> 4;
				subkey[2*i-1]=KHigh^KLow;
			}
		}
		reversesubkey(subkey);
	}
    return subkey;
}
unsigned char* encry_decry(unsigned char input[4],unsigned char *key,unsigned char output[4])
{
	int i;
	unsigned int S1,S2;
	unsigned char L[2],R[2],tempL[2],K[2],bit[16];
	L[0]=input[0];L[1]=input[1];
	R[0]=input[2];R[1]=input[3];
	
	K[0]=K[1]='0'^'0';

	for(i=1;i<=ROUNDS;i++)
	{
		tempL[0]=L[0];tempL[1]=L[1];
		L[0]=R[0];L[1]=R[1];

		//f(R,K)^L=R    F-function
		//XOR  byte > int 
		S1=R[0]^key[2*i-2];S2=R[1]^key[2*i-1];
		//0 > 256
		if(S1==0)S1=256;
		if(S2==0)S2=256;
		//Extended-Euclid Algorithm
		S1=Ex_Euclid(S1,257);
		S2=Ex_Euclid(S2,257);
		//affine cipher under mod 2^8+1
        //S-function
		S1=(A*S1+B)%257;
		S2=(A*S2+B)%257;

		if(S1==256)S1=0;
		if(S2==256)S2=0;

		R[0]=S1;R[1]=S2;
		bit[0]=R[0]&128;
		bit[1]=R[0]&64;
		bit[2]=R[0]&32;
		bit[3]=R[0]&16;
		bit[4]=R[0]&8;
		bit[5]=R[0]&4;
		bit[6]=R[0]&2;
		bit[7]=R[0]&1;
		bit[8]=R[1]&128;
		bit[9]=R[1]&64;
		bit[10]=R[1]&32;
		bit[11]=R[1]&16;
		bit[12]=R[1]&8;
		bit[13]=R[1]&4;
		bit[14]=R[1]&2;
		bit[15]=R[1]&1;

        //P-function
		//P-box
		/*
			9  5  3  2
			13 7  4 14 
            11 6  15 8
			16 12 10 1
		*/
		R[0]=R[1]='0'^'0';

        /*:P盒(置换函数)原理
          P[i][j]表示第(j*4+i)位需要置换到P[i][j]位
          如第一行第一列的9表示bit[0]置换到bit[9]
          依此类推..
        */
		                   R[1]|=bit[0];
		bit[1]=bit[1] >> 3;R[0]|=bit[1];
		                   R[0]|=bit[2];
		bit[3]=bit[3] << 2;R[0]|=bit[3];
		                   R[1]|=bit[4];
		bit[5]=bit[5] >> 1;R[0]|=bit[5];
		bit[6]=bit[6] << 3;R[0]|=bit[6];
		bit[7]=bit[7] << 1;R[1]|=bit[7];
		bit[8]=bit[8] >> 2;R[1]|=bit[8];
		bit[9]=bit[9] >> 4;R[0]|=bit[9];
		bit[10]=bit[10] >> 4;R[1]|=bit[10];
		bit[11]=bit[11] >> 4;R[0]|=bit[11];
		bit[12]=bit[12] >> 3;R[1]|=bit[12];
		bit[13]=bit[13] << 2;R[1]|=bit[13];
		bit[14]=bit[14] << 5;R[1]|=bit[14];
		bit[15]=bit[15] << 7;R[0]|=bit[15];
		
		//XOR
		R[0]=tempL[0]^R[0];R[1]=tempL[1]^R[1];
		
	}
	output[0]=L[0];output[1]=L[1];output[2]=R[0];output[3]=R[1];
	return  output;
}
void exchange(unsigned char *text)
{
	unsigned char temp[2];
	temp[0]=text[2];temp[1]=text[3];
	text[2]=text[0];text[3]=text[1];
	text[0]=temp[0];text[1]=temp[1];
}
void en_file(FILE *fp,FILE *fp2,unsigned char *key)
{
	int read;
	unsigned char plaintext[4],enctext[4],*p;	
	read=fread(plaintext,1,4,fp);
	if(read==0)
		return;
	do
	{
		p=encry_decry(plaintext,key,enctext);
		fwrite(p,1,4,fp2);
		read=fread(plaintext,1,4,fp);
		
	}while(read==4);
	
	fwrite(plaintext,1,read,fp2); 

}

void de_file(FILE *fp,FILE *fp2,unsigned char *key)
{
	int read;
	unsigned char plaintext[4],enctext[4],*p;
	read=fread(plaintext,1,4,fp);
	if(read==0)
		return;	
	do
	{
		exchange(plaintext);
		p=encry_decry(plaintext,key,enctext);
		exchange(p);
		fwrite(p,1,4,fp2);			
		read=fread(plaintext,1,4,fp);
	}while(read==4);
	
	fwrite(plaintext,1,read,fp2);
}
//we assume that the input is  valid here, say unsigned int 0 ~ 2^16-1 (65535) 
void convert_input_to_key(char *input,unsigned char*key)
{
	int i,l=0,num=0,high,low; 
	for(i=0;input[i]!='\0';i++)
		l++;
	for(i=0;i<l;i++)
	{
		num*=10;
        //0~9's ASCII:48-57
		num+=(input[i]-48);	
	}
	high=num >> 8;
	low=num % 256;
	key[3]=low;
	key[2]=high;
    //input key range:0~2^(16-1),so bit 31 to bit 16(from right to left) is not used and set to 0!
	key[1]=key[0]=0;
    //chaonin 17/1/3 debug
    printf("input key(32bits) via converted is:\n");
    for(i=0;i<4;i++)
        printf("%d ",key[i]);
    printf("\n");
}
void print_usage()
{
	printf("\n usage: cipher e/d file1 file2 key\n");
	printf(" e	to encrypt file1, then write to file2\n");
	printf(" d	to decrypt file1, then write to file2\n");
	printf(" file1	the name of the file to encrypt/decrypt\n");
	printf(" file2	the name of the file to write\n");
	printf(" key	the private raw key\n\n");
}
int main(int argc,char*argv[])
{
	unsigned char key[4],subkey[16],*ptr_k;
	char tag[7];
	char input_key[32];
	FILE * fp,*fp2;
    int i,j;
	if(argc==1)
	{
		print_usage();
		return 0;
	}
	else if(argc==2||argc==3||argc==4||argc>5)
	{
	    //if test
        strcpy(tag,argv[1]);
        if ( tag[0] == 't' )
        {
            int result;
            result = Ex_Euclid(43,257);
            printf("%d\n",result);
            return 1;
        }       
		if(!strcmp("-H",tag)||!strcmp("-h",tag)||!strcmp("-help",tag))
		{
			print_usage();
		}
        else
		{
			printf(" wrong parameters\n");	
			print_usage();
		}
		return 0;
	}

	strcpy(input_key,argv[4]);
    //convert input(16bits key) private raw key to 32bits key
	convert_input_to_key(input_key,key);

	if((fp=fopen(argv[2],"rb"))==NULL)
	{
		printf("open %s failure\n",argv[2]);
		return 0;
	}
	if((fp2=fopen(argv[3],"ab"))==NULL)
	{
		printf("open %s failure\n",argv[3]);
		return 0;
	}
   
    //generate the subkeys... 
	ptr_k=key_schedule(key,subkey,tag[0]);
    //chaonin:  for test!
    //chaonin 17/1/3 debug
    printf("subkey is: \n");
    for(i=0;i<16;i++){
        for(j=0;j<8;j++)
        if(((ptr_k[i]<<j)&128) == 128)
            printf("1");
        else printf("0");
        if (i%2==1)printf("|");
    }
    printf("\n");

	if(tag[0]=='e')
		en_file(fp,fp2,ptr_k);
	else if(tag[0]=='d')
		de_file(fp,fp2,ptr_k);
	else  
	{
		printf(" wrong parameters\n");
		return 0;
	}

	fclose(fp);
	fclose(fp2);

	return 1;
}

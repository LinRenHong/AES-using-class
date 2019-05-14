//
//  main.cpp
//  AES(RenHong)
//
//  Created by 林仁鴻 on 2019/4/24.
//  Copyright © 2019 林仁鴻. All rights reserved.
//


#include <iostream>
#include <stdio.h>
#include "AES.h"

using namespace std;

/*
 1.加解密區塊數目(Nb) :欲加解密的資訊，以 32bits(=1word)為一區塊單位。
 2.金鑰區塊數目(Nk) ：金鑰長度,以 32bits (=1word)為一區塊單位。
 3.運算回合次數(Nr)：加密及解密編解碼的運算回合次數。
 AES-128
 Nb = 4
 Nk = 4
 Nr = 10
 
 AES-192
 Nr = 12
 Nk = 6
 
 AES-256
 Nr = 14
 Nk = 8
 */

int main()
{
    
    AES myAes;
    //    int a = 0x57, b = 0x83;
    //    int c = myAes.GFM( a, b );
    //    printf( "%x * %x = %x\n", a, b, c );
    
//    unsigned char state[][ 4 ] =
//    {
//        { 0xd4, 0xe0, 0xb8, 0x1e },
//        { 0xbf, 0xb4, 0x41, 0x27 },
//        { 0x5d, 0x52, 0x11, 0x98 },
//        { 0x30, 0xae, 0xf1, 0xe5 }
//    };
    
    unsigned char state[][ 4 ] =
    {
        { 0x32, 0x88, 0x31, 0xe0 },
        { 0x43, 0x5a, 0x31, 0x37 },
        { 0xf6, 0x30, 0x98, 0x07 },
        { 0xa8, 0x8d, 0xa2, 0x34 }
    };
    
    unsigned char Key[] = { 0X2b, 0X7e, 0X15, 0X16,
                            0X28, 0Xae, 0Xd2, 0Xa6,
                            0Xab, 0Xf7, 0X15, 0X88,
                            0X09, 0Xcf, 0X4f, 0X3c };
    
    int Nk = 4;
    int Nr = 10;
    int size = Nk * Nr + 1;
    unsigned int w[ size ];
    
    cout << "Before encrypt :" << endl;
    myAes.showState( state );
    
    cout << "-----------------------------------------------------------" << endl << endl;
    
    myAes.keyExpansion( Key, w );
    
    myAes.isEncryptShowStatus = false;
    myAes.encrypt( state, w );
    
    cout << "After encrypt :" << endl;
    myAes.showState( state );
    
    cout << "-----------------------------------------------------------" << endl << endl;
    
    myAes.isDecryptShowStatus = false;
    myAes.decrypt( state, w );
    
    cout << "After decrypt :" << endl;
    myAes.showState( state );
    
    cout << endl;
}


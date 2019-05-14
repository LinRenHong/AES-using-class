//
//  Created by 林仁鴻 on 2019/4/23.
//  Copyright © 2019 林仁鴻. All rights reserved.
//




#include "AES.h"
#include <stdio.h>


AES::AES()
: isInEncrypting( false ), isEncryptShowStatus( false ), isInDecrypting( false ), isDecryptShowStatus( false )
{
    makeT();
    makeRcon();
}


unsigned char AES::GFM( unsigned char a, unsigned char b )
{
    unsigned char c = 0;

    for( int i = 7; i >= 1; i-- )
    {
        c = c ^ ( ( a >> i ) & 0x01 ) * b;
        c = ( c << 1 ) ^ ( ( c >> 7 ) & 0x01 ) * 27;
    }
    
    c = c ^ ( a & 0x01 ) * b;
    
    return c;
}


unsigned char AES::inv( unsigned char a )
{
    unsigned char inva;
    inva = 1;

    for( int i = 0; i < 254; i++ )
        inva = GFM( inva, a );

    return inva;
}


unsigned char AES::effinv( unsigned char a )
{
    int a2, c1;
    a2 = GFM( a, a );
    c1 = 1;

    for( int i = 1; i < 8; i++ )
    {
      c1 = GFM( c1, a2 );
      a2 = GFM( a2, a2 );
    }

    return c1;
}


void AES::encrypt( unsigned char state[][ 4 ], unsigned int *w )
{
    isInEncrypting = true;

    unsigned int key[ 4 ];
    int Nr = 10;

    if( isEncryptShowStatus )
        printf( "Start Encrypting...\n\n" );

    for( int i = 0; i < 4; i++ )
        key[ i ] = w[ i ];

    addRoundKey( state, key );

    for( int round = 1; round < Nr; round++ )
    {
        subBytes( state );

        shiftRow( state );

        mixColumns( state );

        for( int i = 0; i < 4; i++ )
            key[ i ] = w[ 4 * round + i ];

        addRoundKey( state, key );
    }

    subBytes( state );

    shiftRow( state );

    for( int i = 0; i < 4; i++ )
        key[ i ] = w[ 4 * Nr + i ];

    addRoundKey( state, key );

    isInEncrypting = false;
}


void AES::decrypt( unsigned char state[][ 4 ], unsigned int *w )
{
    isInDecrypting = true;

    unsigned int key[ 4 ];
    int Nr = 10;

    if( isDecryptShowStatus )
        printf( "Start Decrypting...\n\n" );

    for( int i = 0; i < 4; i++ )
        key[ i ] = w[ 4 * Nr + i ];

    addRoundKey( state, key );

    for( int round = Nr - 1; round > 0; round-- )
    {
        invShiftRow( state );

        invSubBytes( state );

        for( int i = 0; i < 4; i++ )
            key[ i ] = w[ 4 * round + i ];

        addRoundKey( state, key );

        invMixColumns( state );
    }

    invShiftRow( state );

    invSubBytes( state );

    for( int i = 0; i < 4; i++ )
        key[ i ] = w[ i ];

    addRoundKey( state, key );

    isInDecrypting = false;
}


unsigned int AES::rotWord( unsigned int wt )
{
    wt = ( wt << 8 ) | ( wt >> 24 );
    return wt;
}


unsigned int AES::subWord( unsigned int wt )
{
    wt=( S_Box[ ( wt >> 24 ) & 0xff ] << 24 ) | ( S_Box[ ( wt >> 16 ) & 0xff ] << 16 )
        | ( S_Box[ ( wt >> 8 ) & 0xff ] << 8 ) | ( S_Box[ ( wt ) & 0xff ] );
    return wt;

}


void AES::keyExpansion( unsigned char *key, unsigned int *w )
{
    unsigned int temp;
    int i;
    int Nk = 4;
    i = 0;

    while( i < Nk )
	{
        w[ i ] = ( key[ 4 * i ] << 24 ) | ( key[ 4 * i + 1 ] << 16 )
                | ( key[ 4 * i + 2 ] << 8 ) | ( key[ 4 * i + 3 ] );
        i++;
	}

    i = Nk;
    while( i < 44 )
    {
        temp = w[ i - 1 ];
        if( i % Nk == 0 )
            temp = subWord( rotWord( temp ) ) ^ Rcon[ ( i / Nk ) - 1 ];

        w[ i ] = w[ i - Nk ] ^ temp;
        i++;
    }

}


void AES::shiftRow( unsigned char state[][ 4 ] )
{
    unsigned int r[ 4 ] = {};

    for( int i = 0; i < 4; i++ )
        r[ i ] = state[ i ][ 0 ] << 24 | state[ i ][ 1 ] << 16 | state[ i ][ 2 ] << 8 | state[ i ][ 3 ];

    r[ 1 ] = ( r[ 1 ] << 8 ) | ( r[ 1 ] >> 24 );
    r[ 2 ] = ( r[ 2 ] << 16 ) | ( r[ 2 ] >> 16 );
    r[ 3 ] = ( r[ 3 ] << 24 ) | ( r[ 3 ] >> 8 );

    for( int i = 0; i < 4; i++ )
    {
        state[ i ][ 0 ] = r[ i ] >> 24 & 0xff;
        state[ i ][ 1 ] = r[ i ] >> 16 & 0xff;
        state[ i ][ 2 ] = r[ i ] >> 8 & 0xff;
        state[ i ][ 3 ] = r[ i ] & 0xff;
    }

    if( isEncryptShowStatus )
    {
        printf( "After ShiftRow :\n" );
        showState( state );
    }
}


void AES::subBytes( unsigned char state[][ 4 ] )
{
//    for( int r = 0; r < 4; r++ )
//        for( int c = 0; c < 4; c++ )
//            state[ r ][ c ] = S_Box[ state[ r ][ c ] ];

    unsigned int r[ 4 ] = {};

    for( int i = 0; i < 4; i++ )
    {
        r[ i ] = state[ i ][ 0 ] << 24 | state[ i ][ 1 ] << 16 | state[ i ][ 2 ] << 8 | state[ i ][ 3 ];

        r[ i ] = ( S_Box[ ( r[ i ] >> 24 ) & 0xff ] << 24 ) | ( S_Box[ ( r[ i ] >> 16 ) & 0xff ] << 16 )
                | ( S_Box[ ( r[ i ] >> 8 ) & 0xff ] << 8 ) | ( S_Box[ ( r[ i ] ) & 0xff ] );

        state[ i ][ 0 ] = r[ i ] >> 24 & 0xff;
        state[ i ][ 1 ] = r[ i ] >> 16 & 0xff;
        state[ i ][ 2 ] = r[ i ] >> 8 & 0xff;
        state[ i ][ 3 ] = r[ i ] & 0xff;
    }

    if( isEncryptShowStatus )
    {
        printf( "After SubBytes :\n" );
        showState( state );
    }
}


void AES::mixColumns( unsigned char state[][ 4 ] )
{
//    unsigned char t[ 4 ];
//    int r, c;
//    for ( int c = 0; c < 4; c++ )
//    {
//        for ( r = 0; r < 4; r++ )
//            t[ r ] = state[ r ][ c ];
//
//        for ( r = 0; r < 4; r++ )
//        {
//            state[ r ][ c ] = GFM( 0x02, t[ r ] )
//            ^ GFM( 0x03, t[ ( r + 1 ) % 4 ] )
//            ^ GFM( 0x01, t[ ( r + 2 ) % 4 ] )
//            ^ GFM( 0x01, t[ ( r + 3 ) % 4 ] );
//        }
//    }

    unsigned char a0, a1, a2, a3, c0, c1, c2, c3;

    a0 = 02;
    a1 = 03;
    a2 = 01;
    a3 = 01;

    for( int i = 0; i < 4; i++ )
    {
        c0 = GFM( state[ 0 ][ i ], a0 ) ^ GFM( state[ 1 ][ i ], a1 ) ^ GFM( state[ 2 ][ i ], a2 ) ^ GFM( state[ 3 ][ i ], a3 );
        c1 = GFM( state[ 0 ][ i ], a3 ) ^ GFM( state[ 1 ][ i ], a0 ) ^ GFM( state[ 2 ][ i ], a1 ) ^ GFM( state[ 3 ][ i ], a2 );
        c2 = GFM( state[ 0 ][ i ], a2 ) ^ GFM( state[ 1 ][ i ], a3 ) ^ GFM( state[ 2 ][ i ], a0 ) ^ GFM( state[ 3 ][ i ], a1 );
        c3 = GFM( state[ 0 ][ i ], a1 ) ^ GFM( state[ 1 ][ i ], a2 ) ^ GFM( state[ 2 ][ i ], a3 ) ^ GFM( state[ 3 ][ i ], a0 );
        state[ 0 ][ i ] = c0;
        state[ 1 ][ i ] = c1;
        state[ 2 ][ i ] = c2;
        state[ 3 ][ i ] = c3;
    }

    if( isEncryptShowStatus )
    {
        printf( "After MixColumns :\n" );
        showState( state );
    }
}

void AES::addRoundKey( unsigned char state[][ 4 ], unsigned int *key )
{
    unsigned int r[ 4 ] = {};

    for( int i = 0; i < 4; i++ )
    {
        r[ i ] = state[ 0 ][ i ] << 24 | state[ 1 ][ i ] << 16 | state[ 2 ][ i ] << 8 | state[ 3 ][ i ];
        r[ i ] ^= key[ i ];
    }

    for( int i = 0; i < 4; i++ )
    {
        state[ 0 ][ i ] = r[ i ] >> 24 & 0xff;
        state[ 1 ][ i ] = r[ i ] >> 16 & 0xff;
        state[ 2 ][ i ] = r[ i ] >> 8 & 0xff;
        state[ 3 ][ i ] = r[ i ] & 0xff;
    }

    if( ( isInEncrypting && isEncryptShowStatus ) || ( isInDecrypting && isDecryptShowStatus ) )
    {
        printf( "After AddRoundKey :\n" );
        showState( state );
    }
}


void AES::invShiftRow( unsigned char state[][ 4 ] )
{
    unsigned int r[ 4 ] = {};

    for( int i = 0; i < 4; i++ )
        r[ i ] = state[ i ][ 0 ] << 24 | state[ i ][ 1 ] << 16 | state[ i ][ 2 ] << 8 | state[ i ][ 3 ];

    r[ 1 ] = ( r[ 1 ] >> 8 ) | ( r[ 1 ] << 24 );
    r[ 2 ] = ( r[ 2 ] >> 16 ) | ( r[ 2 ] << 16 );
    r[ 3 ] = ( r[ 3 ] >> 24 ) | ( r[ 3 ] << 8 );

    for( int i = 0; i < 4; i++ )
    {
        state[ i ][ 0 ] = r[ i ] >> 24 & 0xff;
        state[ i ][ 1 ] = r[ i ] >> 16 & 0xff;
        state[ i ][ 2 ] = r[ i ] >> 8 & 0xff;
        state[ i ][ 3 ] = r[ i ] & 0xff;
    }

    if( isDecryptShowStatus )
    {
        printf( "After invShiftRow :\n" );
        showState( state );
    }
}



void AES::invSubBytes( unsigned char state[][ 4 ] )
{
    unsigned int r[ 4 ] = {};

    for( int i = 0; i < 4; i++ )
    {
        r[ i ] = state[ i ][ 0 ] << 24 | state[ i ][ 1 ] << 16 | state[ i ][ 2 ] << 8 | state[ i ][ 3 ];

        r[ i ] = ( invS_Box[ ( r[ i ] >> 24 ) & 0xff ] << 24 ) | ( invS_Box[ ( r[ i ] >> 16 ) & 0xff ] << 16 )
                | ( invS_Box[ ( r[ i ] >> 8 ) & 0xff ] << 8 ) | ( invS_Box[ ( r[ i ] ) & 0xff ] );


        state[ i ][ 0 ] = r[ i ] >> 24 & 0xff;
        state[ i ][ 1 ] = r[ i ] >> 16 & 0xff;
        state[ i ][ 2 ] = r[ i ] >> 8 & 0xff;
        state[ i ][ 3 ] = r[ i ] & 0xff;
    }

    if( isDecryptShowStatus )
    {
        printf( "After invSubBytes :\n" );
        showState( state );
    }
}


void AES::invMixColumns( unsigned char state[][ 4 ] )
{
    unsigned char a0, a1, a2, a3, c0, c1, c2, c3;

    a0 = 0x0e;
    a1 = 0x0b;
    a2 = 0x0d;
    a3 = 0x09;

    for( int i = 0; i < 4; i++ )
    {
        c0 = GFM( state[ 0 ][ i ], a0 ) ^ GFM( state[ 1 ][ i ], a1 ) ^ GFM( state[ 2 ][ i ], a2 ) ^ GFM( state[ 3 ][ i ], a3 );
        c1 = GFM( state[ 0 ][ i ], a3 ) ^ GFM( state[ 1 ][ i ], a0 ) ^ GFM( state[ 2 ][ i ], a1 ) ^ GFM( state[ 3 ][ i ], a2 );
        c2 = GFM( state[ 0 ][ i ], a2 ) ^ GFM( state[ 1 ][ i ], a3 ) ^ GFM( state[ 2 ][ i ], a0 ) ^ GFM( state[ 3 ][ i ], a1 );
        c3 = GFM( state[ 0 ][ i ], a1 ) ^ GFM( state[ 1 ][ i ], a2 ) ^ GFM( state[ 2 ][ i ], a3 ) ^ GFM( state[ 3 ][ i ], a0 );
        state[ 0 ][ i ] = c0;
        state[ 1 ][ i ] = c1;
        state[ 2 ][ i ] = c2;
        state[ 3 ][ i ] = c3;
    }

    if( isDecryptShowStatus )
    {
        printf( "After invMixColumns :\n" );
        showState( state );
    }
}


void AES::showState( unsigned char state[][ 4 ] )
{
    for( int i = 0; i < 4; i++ )
        printf( "%.2x %.2x %.2x %.2x\n", state[ i ][ 0 ], state[ i ][ 1 ], state[ i ][ 2 ], state[ i ][ 3 ] );

    printf( "\n" );
}


void AES::makeT()
{
    unsigned char affine[] = { 0xf1, 0xe3, 0xc7, 0x8f,
                               0x1f, 0x3e, 0x7c, 0xf8 };

    unsigned char t, tb, b1, b, c;

	c = 0x63;

	for( int a = 0; a < 256; a++ )
	{
        b = effinv( a );
        b1 = 0;

        for( int i = 0; i < 8; i++ )
        {
           t = affine[ i ] & b;
           tb = 0;
           for( int j = 0; j < 8; j++ )
              tb = tb ^ ( ( t >> j ) & 0x01 );

           b1 = b1 | ( tb << i );
        }

        b1 = b1 ^ c;
        S_Box[ a ] = b1;
    }
}


void AES::makeRcon()
{
    unsigned int x = 1;

    for( int i = 0; i < 10; i++ )
    {
        Rcon[ i ] = x << 24;
        x = GFM( x, 2 );
    }
}


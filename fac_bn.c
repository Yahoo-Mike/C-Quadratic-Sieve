///////////////////////////////////////////////////////////////////////////////
// 
//  * big integer support with OpenSSL "BIGNUM"
//  * convert between "BIGNUM" and qs "cint" large integers
//  * extend OpenSSL BN library with BN_inc(), BN_log()
//  * some testing functions and extra integrity checks (-DFAC_TEST)
//
///////////////////////////////////////////////////////////////////////////////

#include <math.h>           // log10()  log()
#include <openssl/bn.h>     // OpenSSL BIGNUM support

//#define FAC_TEST  // for extra integrity checks and test functions (or compile with -DFAC_TEST)

// converts cint to BIGNUM
//  IN: c  - ptr to cint to convert
//  IN: bn - ptr to BIGNUM to populate
// OUT: bn - holds converted value of cint large number
//           Will hold 0 if c==NULL
static void cint2bn(BIGNUM *bn, const cint *c) {
    if (bn == NULL) return;
    if (c == NULL) {
        BN_zero(bn);
        return;
    }

    char *_tmp = cint_to_string(c, 10);
    BN_dec2bn(&bn, _tmp);

#ifdef FAC_TEST
    // integrity checks
    char *x = BN_bn2dec(bn);
    assert(strlen(x) == strlen(_tmp));       // same length
    assert(memcmp(x, _tmp, strlen(x)) == 0); // same contents
    OPENSSL_free(x);
#endif

    free(_tmp);
    return;
}

// converts BIGNUM to cint
//  IN: bn  - ptr to BIGNUM to convert
//  IN: c   - ptr to cint to populate
// OUT: c   - holds converted value of BIGNUM large number
//            Will hold 0 if bn==NULL
static void bn2cint(cint *c, const BIGNUM *bn) {
    if (c == NULL) return;
    if (bn == NULL) {
        cint_erase(c);
        return;
    }

    char *_bn = BN_bn2dec(bn);
	cint_reinit_by_string(c, _bn, 10);

#ifdef FAC_TEST
	// integrity checks
	char *x = cint_to_string(c,10);
	assert(strlen(x)==strlen(_bn));	// same length
	assert(memcmp(x,_bn,strlen(x))==0);	// same contents
    free(x);
#endif    

    OPENSSL_free(_bn);
    return;
}

///////////////////////////////////////////////////////////////////////////////
// extend OpenSSL BN library
///////////////////////////////////////////////////////////////////////////////

// increment and decrement
#define BIG_inc(X) BN_add_word(X,1)
#define BIG_dec(X) BN_sub_word(X,1)

// base-10 log
// https://stackoverflow.com/a/70384828/13546494
// IN:  X - ptr to BIGNUM to operate on
// RETURN: base-10 log(X)
// ON ERROR: asserts
static double BIG_log10(const BIGNUM *X)
{
    double d = 0.0;

    assert( !BN_is_negative(X) ); // BIGNUM must be +ve

    char *strx = BN_bn2dec(X);
    size_t strxlen = strlen(strx);

    char *stry = (char*)malloc(strxlen + 1 + 2); //strxlen + NULL-terminator + "0."
    assert(stry != NULL);

    sprintf(stry, "0.%s", strx);

    int rc = sscanf(stry, "%lf", &d);
    assert(rc == 0);

    OPENSSL_free(strx);
    free(stry);

    return strxlen + log10(d);
}

// natural (base-e) log
// https://stackoverflow.com/a/70384828/13546494
// IN:  X - ptr to BIGNUM to operate on
// RETURN: natural log(X)
// ON ERROR: asserts
static double BIG_log(const BIGNUM *X)
{
    return BIG_log10(X) * log(10.0);
}


///////////////////////////////////////////////////////////////////////////////
// test function
///////////////////////////////////////////////////////////////////////////////

#ifdef FAC_TEST
// simple test function of the proposition: (B * B) % A = kN % A
// IN: qs - qs_sheet containing quadratic variables A & B and constant kN to test
static void assert_truth(const qs_sheet* qs)
{
    bool good = true;

    const cint *A = &qs->poly.A;
    const cint *B = &qs->poly.B;
    const cint *kN = &qs->constants.kN;

    // constants
    BIGNUM *bnkN = qs->bn1;
    BIGNUM *bnA  = qs->bn2;
    BIGNUM *bnB  = qs->bn3;
    cint2bn(bnkN, kN);
    cint2bn(bnA, A);
    cint2bn(bnB, B);

    char *_A  = BN_bn2dec(bnA);
    char *_B  = BN_bn2dec(bnB);
    char *_kN = BN_bn2dec(bnkN);

    BIGNUM *bnB2 = qs->bn4;
    BN_sqr(bnB2, bnB, qs->ctx);       // bnB2 = bnB^2

    // assertion: (B * B) % A = kN % A
    BIGNUM *R1 = qs->bn5;
    BN_mod(R1, bnB2, bnA, qs->ctx);
    BIGNUM *R2 = qs->bn6;
    BN_mod(R2, bnkN, bnA, qs->ctx);

    if ( BN_cmp(R1, R2) ) {
        printf("BAD\n");    // R1 != R2
        good = false;
    } else
        printf("GOOD\n");   // R1 == R2

    char *_B2 = BN_bn2dec(bnB2);
    printf(" A = %s\n", _A);
    printf(" B = %s\n", _B);
    printf("B2 = %s\n", _B2);
    printf("kN = %s\n", _kN);

    char *_R1 = BN_bn2dec(R1);
    char *_R2 = BN_bn2dec(R2);
    printf(" ==> (B^2) mod A = %s\n", _R1);
    printf("        kN mod A = %s\n", _R2);

    OPENSSL_free(_A);  OPENSSL_free(_B);  OPENSSL_free(_kN);  OPENSSL_free(_B2);
    OPENSSL_free(_R1);
    OPENSSL_free(_R2);

    assert( good );
    return;
}
#endif
#include "ossllib.h"

int save_pubkey(const char *fname, RSA *rsa)
{

    BIO *bp = BIO_new_file(fname, "w+");
    if (bp)
    {
        int rc = PEM_write_bio_RSAPublicKey(bp, rsa);
        BIO_free(bp);
        if (rc != 1)
            return EPEMWRFL;
        return LICENSE_SUCCESS;
    }
    else
        return EPEMFAIL;
}

RSA *load_pubkey(const char *fname)
{

    BIO *bp = BIO_new_file(fname, "r");
    if (bp)
    {
        RSA *rc = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
        BIO_free(bp);
        if (!rc)
            return NULL;
        return rc;
    }

    return NULL;
}

int save_prikey(const char *fname, RSA *rsa)
{

    BIO *bp = BIO_new_file(fname, "w+");
    if (bp)
    {
        int rc = PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, (void *)u);
        BIO_free(bp);
        if (rc != 1)
            return(EPEMWRFL);
        return LICENSE_SUCCESS;
    }
    else
        return(EPEMFAIL);
}

RSA *load_prikey(const char *fname)
{

    BIO *bp = BIO_new_file(fname, "r");
    if (bp)
    {
        RSA *rc = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, (void *)u);
        BIO_free(bp);
        if (!rc)
            return NULL;
        return rc;
    } 

    return NULL;
}

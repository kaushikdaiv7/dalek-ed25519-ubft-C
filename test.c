#include <stdio.h>
#include "ed25519.h"

#include "ge.h"
#include "sc.h"


int main() {
    unsigned char public_key[32], private_key[64], seed[32], signature[64];

    // datatype used by ubft
    const uint8_t message[] = {255, 254, 253};
    const int message_len = sizeof(message);

    /* create a random seed, and a keypair out of that seed */
    ed25519_create_seed(seed);

    /* create new keypair based on the generated seed*/
    ed25519_create_keypair(public_key, private_key, seed);
    
    /* create signature on the message with the keypair */
    ed25519_sign(signature, message, message_len, public_key, private_key);
        
    /* verify the signature */
    if (ed25519_verify(signature, message, message_len, public_key)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }
    
    return 0;
}

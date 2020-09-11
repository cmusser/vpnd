#include <libgen.h>
#include <stdio.h>
#include <sodium.h>

int
main(int argc, char **argv)
{
	unsigned char	sk[crypto_box_SECRETKEYBYTES];
	unsigned char	pk[crypto_box_PUBLICKEYBYTES];
	char		sk_hex    [(crypto_box_SECRETKEYBYTES * 2) + 1];
	char		pk_hex    [(crypto_box_PUBLICKEYBYTES * 2) + 1];

	if (sodium_init() == -1) {
		printf("failed to initialize crypto library.\n");
		return EXIT_FAILURE;;
	}
	crypto_box_keypair(pk, sk);

	sodium_bin2hex(sk_hex, sizeof(sk_hex), sk, sizeof(sk));
	sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, sizeof(pk));
	printf("# Secret key for local vpnd.conf : %s\n", sk_hex);
	printf("# Public key for peer vpnd.conf  : %s\n", pk_hex);
	return EXIT_SUCCESS;
}

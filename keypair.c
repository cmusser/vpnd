#include <libgen.h>
#include <stdio.h>
#include <sodium.h>

int
main(int argc, char **argv)
{
	unsigned char	sk[crypto_box_SECRETKEYBYTES];
	unsigned char	pk[crypto_box_PUBLICKEYBYTES];
	char		key_fname [256];
	FILE           *key_file;
	char		sk_hex    [(crypto_box_SECRETKEYBYTES * 2) + 1];
	char		pk_hex    [(crypto_box_PUBLICKEYBYTES * 2) + 1];

	if (argc < 2) {
		printf("usage: %s <name>\n", basename(argv[0]));
		return EXIT_FAILURE;
	}
	if (sodium_init() == -1) {
		printf("failed to initialize crypto library.\n");
		return EXIT_FAILURE;;
	}
	crypto_box_keypair(pk, sk);

	snprintf(key_fname, sizeof(key_fname), "%s.keypair", argv[1]);
	key_file = fopen(key_fname, "w");
	if (key_file == NULL) {
		perror("fopen");
		return EXIT_FAILURE;
	}
	sodium_bin2hex(sk_hex, sizeof(sk_hex), sk, sizeof(sk));
	sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, sizeof(pk));
	fprintf(key_file, "secret: %s\n", sk_hex);
	fprintf(key_file, "public: %s\n", pk_hex);

	return EXIT_SUCCESS;
}

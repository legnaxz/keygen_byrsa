#include <stdio.h>
#include "rsa.h"
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>

int main (int argc, char **argv)
{
	FILE *fp = NULL;
	char *KEY_PATH = "./key.lic";
	struct public_key_class pub[1];
	struct private_key_class priv[1];
	_rsa_gen_keys (pub, priv);
	unsigned char message[6] = { 0, 0, 0, 0, 0, 0 };
	unsigned char year, month, day = 0;
	long long *year_limit, *month_limit, *day_limit;
	int local_argc = argc;
	long long *encrypted;
	int i,j,x = 0;
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);

	fp = fopen(KEY_PATH, "wb");
	year = tm.tm_year - 100;
	month = tm.tm_mon + 1;
	day = tm.tm_mday;

	for ( x = 1; x < argc; x++ ) {
		if( !strcmp(argv[x], "--year") || !strcmp(argv[x], "-Y") ) {
			x++;
			int t = (int)strtol(argv[x], NULL, 10 );
			if( 1 <= t || 10 >= t ) {
				year = year + t;
			}
			else {
				printf("error year [ 1- 10 ] try again. \n");
				exit(1);
			}
		}
		else if( !strcmp(argv[x], "--month") || !strcmp(argv[x], "-M") ) {
			x++;
			int t = (int)strtol(argv[x], NULL, 10 );
			if( 1 <= t || 12 >= t ) {
				month = month + t;
			}
			else {
				printf("error month [ 1- 12 ] try again. \n");
				exit(1);
			}	
		}
		else if( !strcmp(argv[x], "--day") || !strcmp(argv[x], "-D") ) {
			x++;
			int t = (int)strtol(argv[x], NULL, 10 );
			if( 1 <= t || 30 >= t ) {
				day = day + t;
			}	
			else {
				printf("error year [ 1- 30 ] try again. \n");
				exit(1);
			}	
		}
		else if( !strcmp(argv[x], "--addr") || !strcmp(argv[x], "-A") ) {
			x++;
			for( i = 0; i < 6; i++ ) {
				message[i] = (int)strtol(argv[x], NULL, 16);
				x++;
			}
		}
		else {
			printf("Usage : --year or -Y : [1-10],\n --month or -M : [1-12], \n --day or -D : [1-30] \n, you put : %s try again.", argv[x]);
			return 0;	
		}
	}

	if ( day > 31 ) {
		month = month + ( day / 31 );
		day = (day % 31)+1;

		if( month > 12 ) {
			year = year + (month / 12);
			month = (month % 12) + 1;
		}
	}
	if( month > 12 ) {
		year = year + (month / 12);
		month = (month % 12) + 1;
	}

	year_limit = rsa_encrypt(&year, 1, pub);
	month_limit = rsa_encrypt (&month, 1, pub);
	day_limit = rsa_encrypt (&day, 1, pub);
	encrypted = rsa_encrypt (message, sizeof (message), pub);
	if ( !encrypted || !year_limit || !month_limit || !day_limit )
	{
		printf ("Error in encryption!\n");
		return 1;
	}
	fprintf (fp, "%lld\n", (long long) year_limit[0]);
	fprintf (fp, "%lld\n", (long long) month_limit[0]);
	fprintf (fp, "%lld\n", (long long) day_limit[0]);

	for (i = 0; i < 6; i++)
	{
		fprintf (fp, "%lld\n", (long long) encrypted[i]);
	}
	printf("Encrypted. see %s \n", KEY_PATH);
	free( encrypted );
	fclose(fp);
	/*
	   if ( argc < 7 )
	   {
	   printf( "Input your MAC address correctly %d ", argc);
	   exit( 1 );
	   }
	   else
	   {
	   for (i = 0; i < 6; i++)
	   {
	   printf ("%s-", argv[i + 1]);
	   message[i] = (int)strtol(argv[i + 1], NULL, 16);
	   printf("%d/",message[i]);
	   }
	   printf("\n");
	   }

	   long long *encrypted = rsa_encrypt (message, sizeof (message), pub);
	   if (!encrypted)
	   {
	   fprintf (stderr, "Error in encryption!\n");
	   return 1;
	   }

	   fp = fopen (KEY_PATH, "wb");
	   printf ("Encrypted:\n");
	   for (i = 0; i < 6; i++)
	   {
	   printf ("%lld\n", (long long) encrypted[i]);
	   fprintf (fp, "%lld\n", (long long) encrypted[i]);
	   }

	   fclose( fp );
	   free( encrypted );
	   */
	return 0;
}

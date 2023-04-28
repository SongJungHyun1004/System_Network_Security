#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>
#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)
int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char enckey[10] = {0,};
	int len=64;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	char *option = argv[1];
	if(!strcmp(option, "-e")){
		printf("========================Encryption========================\n");
		char *plainfile = argv[2];
		FILE* fp = fopen(plainfile, "r");
		fgets(plaintext, sizeof(plaintext), fp);
		printf("Plaintext: %s\n", plaintext);
		memcpy(op.params[0].tmpref.buffer, plaintext, len);

		char *algorithm = argv[3];
		if(algorithm == NULL){
			printf("missing algorithm\n");
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);
			return 1;
		}
		if(!strcmp(algorithm, "Caesar")){
			printf("==========================Caesar==========================\n");
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
			printf("Ciphertext : %s\n", ciphertext);
			fp = fopen("ciphertext.txt", "w");
			fputs(ciphertext, fp);

			fp = fopen("encryptedkey.txt", "w");
			uint32_t encryptedkey = op.params[1].value.a;
			char temp[5] = {0,};
			sprintf(temp, "%d\n", encryptedkey);
			fputs(temp, fp);
			fclose(fp);
		}
		else if(!strcmp(algorithm, "RSA")){
			printf("===========================RSA============================\n");
			op.params[2].tmpref.buffer = plaintext;
			op.params[2].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
			op.params[3].tmpref.buffer = ciphertext;
			op.params[3].tmpref.size = RSA_CIPHER_LEN_1024;

			res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_GENKEYS, NULL, NULL);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
			printf("\n=========== Keys already generated. ==========\n");

			res = TEEC_InvokeCommand(&sess, TA_RSA_CMD_ENCRYPT, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n", res, err_origin);

			memcpy(ciphertext, op.params[3].tmpref.buffer, len);
			printf("RSA_Ciphertext : %s\n", ciphertext);
			fp = fopen("rsa_ciphertext.txt", "w");
			fputs(ciphertext, fp);
			fclose(fp);
		}
		else {
			printf("Wrong algorithm.\n");	
		}
	}

	else if(!strcmp(option, "-d")){
		printf("========================Decryption========================\n");
		char *cipherfile = argv[2];
		FILE* fp = fopen(cipherfile, "r");
		fgets(ciphertext, sizeof(ciphertext), fp);
		printf("Ciphertext: %s\n", ciphertext);
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);

		char *enckeyfile = argv[3];
		fp = fopen(enckeyfile, "r");
		fgets(enckey, sizeof(enckey), fp);
		printf("Encrypted Key: %s\n", enckey);
		op.params[1].value.a = atoi(enckey);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("Result Plaintext : %s\n", plaintext);
		fp = fopen("result_plaintext.txt", "w");
		fputs(plaintext, fp);
		fclose(fp);
	}
	else {
		printf("Wrong option.\n");	
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}

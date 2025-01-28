#define _GNU_SOURCE

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <fcntl.h>
#include <math.h>
#include <linux/random.h>

int hmac_dgst(unsigned char* key, unsigned char* hmac_d, uint8_t* counter, int dig);

int view_key();

int get_key(unsigned char* key);

int get_key_pam(pam_handle_t *pamh,unsigned char* key);

int create_key();

int current_state();

int dyn_trun(unsigned char* key,int dig);

int b32_enc(unsigned char* key);

int get_counter(uint8_t *counter, int flag);

int get_counter_pam(pam_handle_t *pamh,uint8_t* counter, int flag);

int inc_counter(int resynch);

int inc_counter_pam(pam_handle_t *pamh,int resynch);

int create_config_file(char * dir,int mode, int counter, int sudo, int su, int login, int ssh);

int select_services();

int verify_serv(int serv);

int test_code(int try);

int test_code_pam(pam_handle_t *pamh,int try);

char * conf_file();

char * conf_file_pam(pam_handle_t *pamh);

char * key_file();

char * key_file_pam(pam_handle_t *pamh);

char * pass_file();

char * pass_file_pam(pam_handle_t *pamh);

int is_hotp();

int is_hotp_pam(pam_handle_t *pamh);

int su_user(char * user);

int login_user(char * user);

int ssh_user(char * user);

void file_lock_init();

int open_r(char * file, char * s, int len);

int open_w(char * file, char * s);

int create_recovery_password();

int magic_check(pam_handle_t *pamh, int try);

int magic_pass_check(pam_handle_t *pamh, char * try);
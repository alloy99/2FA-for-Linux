#define _GNU_SOURCE

#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#define ANSI_COLOR_RED     "\x1b[31m"

#define STYLE_BOLD         "\033[1m"
#define STYLE_NO_BOLD      "\033[22m"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <linux/random.h>
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
#include "2fa_lib.h"

                /* l_type   l_whence  l_start  l_len  l_pid   */
struct flock fl = {F_RDLCK, SEEK_SET,   0,      0,     0 };

/*
Initializes the fl struct with process id.
Always call this at start
*/
void file_lock_init(){
    fl.l_pid = getpid();
}

/*
Opens desired file, reads up to len chars of it, closes it and returns contents using char* s.
Implements file locks, multiple readers.
Returns 0 on success, 1 if file doesn't exist and -1 on error
*/
int open_r(char * file, char * s, int len){
    int fd;

    if(access(file,F_OK)!=0){
        return 1;
    }
    fl.l_type = F_RDLCK;
    fd = open (file,O_RDONLY);
    if (fd<0){
        //printf("ERROR: Could not open file\n");
        return -1;
    }
    else {
        if ((fcntl(fd, F_SETLKW, &fl))==-1){
            //printf("ERROR: Could not aquire lock\n");
            close (fd);
            return -1;
        }
        if((read(fd,s,len))<1){
            //printf("ERROR: No bytes read\n");
            close(fd);
            return -1;
        }
        fl.l_type = F_UNLCK;
        if (fcntl(fd, F_SETLK, &fl) == -1){
            //printf("ERROR: Could not unlock file\n");
            close (fd);
            return -1;
        }
        close(fd);
    }
    return 0;
}

/*
Opens desired file, writes string s to it and closes it.
Implements file locks, 1 writer. No readers while writing.
Returns 0 on success, 1 otherwise.
*/
int open_w(char * file, char * s){
    int fd;

    fl.l_type = F_WRLCK;
    fd = open (file,O_WRONLY);
    if (fd<0){
        printf("ERROR: Could not open file: %s\n",file);
        return 1;
    }
    else {
        if ((fcntl(fd, F_SETLKW, &fl))==-1){
            printf("ERROR: Could not aquire lock\n");
            close (fd);
            return 1;
        }
        if((write(fd,s,strlen(s)))<1){
            printf("ERROR: No bytes written\n");
            close(fd);
            return 1;
        }
        fl.l_type = F_UNLCK;
        if (fcntl(fd, F_SETLK, &fl) == -1){
            printf("ERROR: Could not unlock file\n");
            close (fd);
            return 1;
        }
        close(fd);
    }
    return 0;
}

/*
Checks if [user] has a conf file and if SU service is activated. Returns 0
if file exists and su is activated. 1 Otherwise. Returns -1 in case of error
*/
int su_user(char * user){
    char str[25]="";
    int su,ret;
    char * token=NULL;
    char * dir=malloc ((20+strlen(user)));
    if (!dir){
        printf("Malloc failure! Exiting...");
        return -1;
    }
    memset(dir,0,(20+strlen(user)));
    strcat(dir,"/home/");
    strcat(dir,user);
    strcat(dir,"/2FA/2FA.conf");
    ret=open_r(dir,str,25);
    if (ret==-1){
        return -1;
    }
    else if (ret==1){
        return 1;
    }
    else {
        token = strtok(str,",");
        token = strtok(NULL,",");
        token = strtok(NULL,",");
        token = strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!\n");
            return -1;
        }
        su = atoi(token);
        if (su!=0 && su!=1){
            printf ("ERROR: Conf file bad format!\n");
            return -1;
        }
        if (su==1){
            return 0;
        }
        if (su==0){
            return 1;
        }
    }
//Should not reach here...
printf("ERROR: Unknown error\n");
return -1;
}

/*
Checks if [user] has a conf file and if login service is activated. Returns 0
if file exists and login is activated. 1 Otherwise. Returns -1 in case of error
*/
int login_user(char * user){
    char str[25]="";
    int su;
    char * token=NULL;
    char * dir=malloc ((20+strlen(user)));
    if (!dir){
        printf("Malloc failure! Exiting...");
        return -1;
    }
    memset(dir,0,(20+strlen(user)));
    strcat(dir,"/home/");
    strcat(dir,user);
    strcat(dir,"/2FA/2FA.conf");
    if (open_r(dir,str,25)!=0){
        return -1;
    }
    else {
        token = strtok(str,",");
        token = strtok(NULL,",");
        token = strtok(NULL,",");
        token = strtok(NULL,",");
        token = strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!\n");
            return -1;
        }
        su = atoi(token);
        if (su!=0 && su!=1){
            printf ("ERROR: Conf file bad format!\n");
            return -1;
        }
        if (su==1){
            return 0;
        }
        if (su==0){
            return 1;
        }
    }
//Should not reach here...
printf("ERROR: Unknown error\n");
return -1;
}

/*
Checks if [user] has a conf file and if ssh service is activated. Returns 0
if file exists and ssh is activated. 1 Otherwise. Returns -1 in case of error
*/
int ssh_user(char * user){
    char str[25]="";
    int ssh;
    char * token=NULL;
    char * dir=malloc ((20+strlen(user)));
    if (!dir){
        printf("Malloc failure! Exiting...");
        return -1;
    }
    memset(dir,0,(20+strlen(user)));
    strcat(dir,"/home/");
    strcat(dir,user);
    strcat(dir,"/2FA/2FA.conf");
    if (open_r(dir,str,25)!=0){
        return -1;
    }
    else {
        token = strtok(str,",");
        token = strtok(NULL,",");
        token = strtok(NULL,",");
        token = strtok(NULL,",");
        token = strtok(NULL,",");
        token = strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!\n");
            return -1;
        }
        ssh = atoi(token);
        if (ssh!=0 && ssh!=1){
            printf ("ERROR: Conf file bad format!\n");
            return -1;
        }
        if (ssh==1){
            return 0;
        }
        if (ssh==0){
            return 1;
        }
    }
//Should not reach here...
printf("ERROR: Unknown error\n");
return -1;
}

//Returns conf file location of user from a PAM HANDLE
char * conf_file_pam(pam_handle_t *pamh){
    int ret=0;
    char *user=NULL;
    ret=pam_get_item(pamh,PAM_USER,(const void **)&user);
    if (ret!=PAM_SUCCESS){
        return NULL;
    }
    struct passwd *passwdEnt = getpwnam(user);
    char *home = passwdEnt->pw_dir;
    char *dir=NULL;

    dir = malloc (strlen(home)+16);
    if (dir==NULL){
        printf("Malloc failure! Exiting...");
        return NULL;
    }

    strcpy(dir,"\0");
    strcat(dir,home);
    strcat(dir,"/2FA/2FA.conf");

    return dir;
}

//Returns key file location of user FROM A PAM HANDLE. Returns NULL on error
char * key_file_pam(pam_handle_t *pamh){
    int ret;
    char *user=NULL;
    ret=pam_get_item(pamh,PAM_USER,(const void **)&user);
    if (ret!=PAM_SUCCESS){
        return NULL;
    }
    struct passwd *passwdEnt = getpwnam(user);
    char *home = passwdEnt->pw_dir;
    char *dir=NULL;

    dir = malloc (strlen(home)+16);
    if (dir==NULL){
        printf("Malloc failure! Exiting...");
        return NULL;
    }

    strcpy(dir,"\0");
    strcat(dir,home);
    strcat(dir,"/2FA/key.k");

    return dir;
}

//Returns pass file location of user FROM A PAM HANDLE. Returns NULL on error
char * pass_file_pam(pam_handle_t *pamh){
    int ret;
    char *user=NULL;
    ret=pam_get_item(pamh,PAM_USER,(const void **)&user);
    if (ret!=PAM_SUCCESS){
        return NULL;
    }
    struct passwd *passwdEnt = getpwnam(user);
    char *home = passwdEnt->pw_dir;
    char *dir=NULL;

    dir = malloc (strlen(home)+16);
    if (dir==NULL){
        printf("Malloc failure! Exiting...");
        return NULL;
    }

    strcpy(dir,"\0");
    strcat(dir,home);
    strcat(dir,"/2FA/shadow");

    return dir;
}

//Returns conf file location of current user
char * conf_file(){
    struct passwd *passwdEnt = getpwuid(getuid());
    char *home = passwdEnt->pw_dir;
    char *dir=NULL;

    dir = malloc (strlen(home)+16);
    if (dir==NULL){
        printf("Malloc failure! Exiting...");
        return NULL;
    }

    strcpy(dir,"\0");
    strcat(dir,home);
    strcat(dir,"/2FA/2FA.conf");

    return dir;
}

//Returns key file location of current user. Returns NULL on error
char * key_file(){
    struct passwd *passwdEnt = getpwuid(getuid());
    char *home = passwdEnt->pw_dir;
    char *dir = malloc (strlen(home)+16);
    if (dir==NULL){
        printf("Malloc failure! Exiting...");
        return NULL;
    }

    strcpy(dir,"\0");
    strcat(dir,home);
    strcat(dir,"/2FA/key.k");

    return dir;
}

//Returns pass file location of current user. Returns NULL on error
char * pass_file(){
    struct passwd *passwdEnt = getpwuid(getuid());
    char *home = passwdEnt->pw_dir;
    char *dir = malloc (strlen(home)+16);
    if (dir==NULL){
        printf("Malloc failure! Exiting...");
        return NULL;
    }

    strcpy(dir,"\0");
    strcat(dir,home);
    strcat(dir,"/2FA/shadow");

    return dir;
}

//Returns 1 if mode of operation == HOTP and 2 on TOTP. -1 in case of error
int is_hotp(){
    char str[25]="";
    char * token=NULL;
    char *s=NULL;
    int mode;

    s=conf_file();
    if (open_r(s,str,25)!=0){
        free(s);
        return -1;
    }
    else {
        token = strtok(str,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        mode = atoi(token);
    }
    free(s);
    if (mode!=1 && mode!=2){
        printf ("ERROR: Conf file bad format!");
        return -1;
    }
    return mode;
}

//Returns 1 if mode of operation == HOTP and 2 on TOTP. -1 in case of error
int is_hotp_pam(pam_handle_t *pamh){
    char str[25]="";
    char * token=NULL;
    char * s=NULL;
    int mode;

    s=conf_file_pam(pamh);
    if (open_r(s,str,25)!=0){
        free(s);
        return -1;
    }
    else {
        token = strtok(str,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        mode = atoi(token);
    }
    free(s);
    if (mode!=1 && mode!=2){
        printf ("ERROR: Conf file bad format!");
        return -1;
    }
    return mode;
}

//Encode BASE32
int b32_enc(unsigned char* key){
    int x;
    uint8_t num;
    char base32 [33]= "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    for (x=0;x<2;x++){

        /*Extract 40 bits in 5 bits chunks and save it
        as int, then prints its corresponding char
        from the base32 table*/
        num=(key[5*x] >> 3);
        if (x>0)
            printf("-");
        printf("%c",base32[num]);
        num=(((key[5*x] << 2) & 0x1F) ^ (key[5*x+1] >> 6));
        printf("%c",base32[num]);
        num=((key[5*x+1] >> 1) & 0x1F);
        printf("%c",base32[num]);
        num=(((key[5*x+1] << 4) & 0x1F) ^ (key[5*x+2] >> 4));
        printf("%c-",base32[num]);
        num=(((key[5*x+2] << 1) & 0x1F) ^ (key[5*x+3] >> 7));
        printf("%c",base32[num]);
        num=((key[5*x+3] >> 2) & 0x1F);
        printf("%c",base32[num]);
        num=(((key[5*x+3] << 3) & 0x1F) ^ (key[5*x+4] >> 5));
        printf("%c",base32[num]);
        num=(key[5*x+4] & 0x1F);
        printf("%c",base32[num]);

    }
    printf("\n");
    return 0;
}

//Gets HMAC(k,m)
int hmac_dgst(unsigned char* key, unsigned char* hmac_d, uint8_t* counter, int dig){

    /*
    int i;
    printf("HMAC message is: ");
    for (i=0;i<8;i++){
        printf("%d",counter[i]);
    }
    printf("\n");
    */

    hmac_d = HMAC(EVP_sha1(), key, 10, counter, 8, NULL, NULL);

    /*
    printf("HMAC is:");
    for (i=0;i<20;i++){
        printf ("%02X", hmac_d[i]);
    }
    printf("\n");
    */

    return dyn_trun(hmac_d,dig);
}

//Get current key from file. Returns 0 on success, 1 on error.
int get_key(unsigned char* key){
    char hex [3]="";
    char *ptr=NULL;
    char *s=NULL;
    int i =0;
    char* pre_key = malloc (21);
    if (!pre_key){
        printf("Malloc failure! Exiting...");
        return 1;
    }
    s=key_file();
    if (open_r(s,pre_key,20)!=0){
        free(s);
        printf ("\nERROR: Keyfile: not found!\n");
        free(pre_key);
        return 1;
    }
    pre_key[20]='\0';
    hex[2]='\0';
    for (i =0;i<10;i++){
        strncpy(&hex[0],&pre_key[i*2],1);
        strncpy(&hex[1],&pre_key[i*2+1],1);
        key[i]=strtol(hex,&ptr,16);
    }

    //Delete memory and free
    memset (pre_key, 0, 21);
    free (pre_key);
    free(s);
    return 0;
}

//Get current key from file. Returns 0 on success, 1 on error.
int get_key_pam(pam_handle_t *pamh,unsigned char* key){
    char hex [3]="";
    char *ptr=NULL;
    char *s=NULL;
    int i =0;
    char* pre_key = malloc (20);
    if (!pre_key){
        printf("Malloc failure! Exiting...");
        return 1;
    }
    s=key_file_pam(pamh);
    if (open_r(s,pre_key,20)!=0){
        free(s);
        printf ("\nERROR: Keyfile: not found!\n");
        free(pre_key);
        return 1;
    }

    hex[2]='\0';
    for (i =0;i<10;i++){
        strncpy(&hex[0],&pre_key[i*2],1);
        strncpy(&hex[1],&pre_key[i*2+1],1);
        key[i]=strtol(hex,&ptr,16);
    }

    //Delete memory and free
    memset (pre_key, 0, 20);
    free (pre_key);
    free(s);
    return 0;
}

//View Current Key (calls get_key) and trasnform to BASE32
int view_key(){
    int res=0;
    unsigned char* key = malloc (10);
    if (!key){
        printf("Malloc failure! Exiting...");
        return 1;
    }
    res=get_key(key);
    if(res==1){
        memset (key, 0, 10);
        free(key);
        return 1;
    }
    //VIEW Key in Base32
    system("clear");
    printf("\nYour current key is:\n");
    b32_enc(key);
    printf("\nUse this key to configure your Google Authenticator App\n");

    memset (key, 0, 10);
    free(key);
    return 0;
}

//Create new Key
int create_key(){
    FILE * fpr;
    int c,i,res;
    int flag=0;
    char *s=NULL;
    char *ch=malloc(2);
    char str[21]={"\0"};
    char hex[3]={"\0"};
    if (!ch){
        printf("Malloc failure! Exiting...");
        return 1;
    }
    unsigned char* key = malloc (10);
    if (!key){
        printf("Malloc failure! Exiting...");
        free(ch);
        return 1;
    }
    //Verify if Keyfile exists, if it doesnt create it
    s=key_file();
    if (open_r(s,str,21)==0){
        while(flag==0){
            printf ("\nWARNING!\nAnother Keyfile has been found. Creating a new key will overwrite this Keyfile as well as Recovery Password and make any previous setups unusable. Are you sure you want to continue? (y/n):\n");
            fgets(ch,2,stdin);
            while((c = getchar()) != '\n' && c != EOF)
                /* discard extra input*/ ;
            switch(ch[0]){
                case 'y':
                    flag =1;
                    system("clear");
                    printf("\nCreating key, this may take a while...\n");
                    fpr = fopen ("/dev/random", "r");
                    if (!fpr){
                        printf("Not able to open /dev/random! Exiting...");
                        free(key);
                        free(ch);
                        free(s);
                        return 1;
                    }
                    fread(key, 1, 10, fpr);
                    fclose(fpr);
                    str[0]='\0';
                    str[20]='\0';
                    hex[2]='\0';
                    for (i=0;i<10;i++){
                        snprintf (hex,3,"%02X", key[i]);
                        strcat(str,hex);
                    }
                    if(open_w(s,str)!=0){
                        printf("keyfile creation failure! Have you Setup first?\nExiting...\n");
                        free(key);
                        free(ch);
                        free(s);
                        return 1;
                    }
                    memset (key, 0, 10);
                    memset (str,0, 20);
                    chmod(s,0600);
                    printf("Key created successfully!\n");
                    res=create_recovery_password();
                    if (res!=0){
                        printf("Recovery Password creation falure!\nExiting...\n");
                        free(key);
                        free(ch);
                        free(s);
                        return 1;
                    }
                    break;
                case 'Y':
                    flag =1;
                    system("clear");
                    printf("\nCreating key, this may take a while...\n");
                    fpr = fopen ("/dev/random", "r");
                    if (!fpr){
                        printf("Not able to open /dev/random! Exiting...");
                        free(key);
                        free(ch);
                        free(s);
                        return 1;
                    }
                    fread(key, 1, 10, fpr);
                    fclose(fpr);
                    str[0]='\0';
                    str[20]='\0';
                    hex[2]='\0';
                    for (i=0;i<10;i++){
                        snprintf (hex,3,"%02X", key[i]);
                        strcat(str,hex);
                    }
                    if(open_w(s,str)!=0){
                        printf("keyfile creation failure! Have you Setup first?\nExiting...\n");
                        free(key);
                        free(ch);
                        free(s);
                        return 1;
                    }
                    memset (key, 0, 10);
                    memset (str,0, 20);
                    chmod(s,0600);
                    printf("Key created successfully!\n");
                    res=create_recovery_password();
                    if (res!=0){
                        printf("Recovery Password creation falure!\nExiting...\n");
                        free(key);
                        free(ch);
                        free(s);
                        return 1;
                    }
                    break;
                case 'n':
                    flag =1;
                    system("clear");
                    //Do nothing
                    break;
                case 'N':
                    flag =1;
                    system("clear");
                    //Do nothing
                    break;
                default:
                    printf("\nInvalid Option.\n");
            }
        }
    }

    else {
        system("clear");
        printf("\nCreating key, this may take a while...\n");
        fpr = fopen ("/dev/random", "r");
        if (!fpr){
            printf("Not able to open /dev/random! Exiting...");
            free(key);
            free(ch);
            free(s);
            return 1;
        }
        fread(key, 1, 10, fpr);
        fclose(fpr);
        str[0]='\0';
        hex[2]='\0';
        for (i=0;i<10;i++){
            snprintf (hex,3,"%02X", key[i]);
            strcat(str,hex);
        }
        if(open_w(s,str)!=0){
            printf("keyfile creation failure! Have you Setup first?\nExiting...\n");
            memset (key, 0, 10);
            memset (str,0, 20);
            free(key);
            free(ch);
            free(s);
            return 1;
        }
        memset (key, 0, 10);
        memset (str,0, 20);
        chmod(s,0600);
        printf("Key created successfully!\n");
        res=create_recovery_password();
        if (res!=0){
            printf("Recovery Password creation falure!\nExiting...\n");
            free(key);
            free(ch);
            free(s);
            return 1;
        }
    }

    free(key);
    free(s);
    free(ch);
    return 0;
}

//Creates new Recovery Password, returns 0 on success, 1 on failure
int create_recovery_password(){
    SHA256_CTX context;
    FILE * fpr;
    int i,mcode;
    uint8_t counter[8];
    uint32_t x;
    const char charset[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*()-+=/?><.";
    char ch[2]={"\0"};
    char salt[8]="";
    char presalt[8]="";
    unsigned char md[32]="";//SHA256 digest size
    char hex[3]="";
    char hash[64+1+8+1]="";//64 from hash, 1 from comma, 8 from salt, 1 for \0
    char * s=NULL;

    char *pass=malloc(21);//20 from pass 1 from \0
    if (!pass){
        printf("Malloc failure! Exiting...");
        return 1;
    }

    unsigned char *rands=malloc(20);
    if(!rands){
        printf("Malloc failure! Exiting...");
        free(pass);
        return 1;
    }
    unsigned char* key = malloc(10);
    if (!key){
        printf("Malloc failure! Exiting...");
        free(pass);
        free(rands);
        return 1;
    }
    unsigned char* hmac_d = malloc (20);
    if (!hmac_d){
        printf("Malloc failure! Exiting...");
        free(pass);
        free(rands);
        free(key);
        return 1;
    }
    s=pass_file();
    printf("Creating magic password, this may take a while...\n\n");
    fpr = fopen ("/dev/random", "r");
    if (!fpr){
            printf("Not able to open /dev/random! Exiting...");
            free(rands);
            free(pass);
            free(key);
            free(hmac_d);
            free(s);
            return 1;
    }
    fread(rands, 1, 20, fpr);
    fread(presalt,1,8,fpr);
    fclose(fpr);
    pass[0]='\0';
    ch[1]='\0';
    //Generating Random Password - 20 Chars
    for (i=0;i<20;i++){
        x=(rands[i] << 24) | (rands[i] << 16) | (rands[i] << 8) | rands[i];
        x=x%(sizeof(charset)-1);//Should be less than 79
        snprintf (ch,2,"%c", charset[x]);
        strncat(pass,ch,1);
    }
    //Generating Random SALT - 8 Chars
    for (i=0;i<8;i++){
        x=(presalt[i] << 24) | (presalt[i] << 16) | (presalt[i] << 8) | presalt[i];
        x=x%(sizeof(charset)-1);//Should be less than 79
        snprintf (ch,2,"%c", charset[x]);
        strncat(salt,ch,1);
    }
    //Initialize SHA256 context
    if(!SHA256_Init(&context)){
        memset (pass, 0, 20);
        memset (rands,0, 20);
        memset (key,0, 10);
        free(key);
        free(hmac_d);
        free(rands);
        free(pass);
        free(s);
    }
    //Update Hash Context sending Salt, then pass
    if(!SHA256_Update(&context, (unsigned char*)salt, strlen(salt))){
        memset (pass, 0, 20);
        memset (rands,0, 20);
        memset (key,0, 10);
        free(key);
        free(hmac_d);
        free(rands);
        free(pass);
        free(s);
    }
    if(!SHA256_Update(&context, (unsigned char*)pass, strlen(pass))){
        memset (pass, 0, 20);
        memset (rands,0, 20);
        memset (key,0, 10);
        free(key);
        free(hmac_d);
        free(rands);
        free(pass);
        free(s);
    }
    //Get HASH
    if(!SHA256_Final(md,&context)){
        memset (pass, 0, 20);
        memset (rands,0, 20);
        memset (key,0, 10);
        free(key);
        free(hmac_d);
        free(rands);
        free(pass);
        free(s);
    }
    for (i=0;i<32;i++){
        snprintf(hex,3,"%02x",md[i]);
        hash[i*2]=hex[0];
        hash[(i*2)+1]=hex[1];
    }
    strncat(hash,",",1);
    strcat(hash,salt);//strcat instead of strncat to get a terminating char
    if(open_w(s,hash)!=0){
        printf("Passfile creation failure!\nExiting...\n");
        memset (rands, 0, 20);
        memset (pass,0, 20);
        memset (key,0, 10);
        free(rands);
        free(key);
        free(hmac_d);
        free(pass);
        free(s);
        return 1;
    }
    if(get_key(key)!=0){
        printf("Couldn't retrieve key\n");
        memset (rands, 0, 20);
        memset (pass,0, 20);
        memset (key,0, 10);
        free(rands);
        free(key);
        free(hmac_d);
        free(pass);
        free(s);
        return 1;
    }
    for (i=0;i<8;i++){
        counter[i]=0;
    }
    mcode=hmac_dgst(key,hmac_d,counter,8);
    printf("These are your "ANSI_COLOR_YELLOW STYLE_BOLD"MAGIC CODE"ANSI_COLOR_RESET STYLE_NO_BOLD" and "ANSI_COLOR_YELLOW STYLE_BOLD"MAGIC PASSWORD"ANSI_COLOR_RESET STYLE_NO_BOLD". You will need them in case you lose access to your Google Authenticator App, it goes out of sync, etc.\n"ANSI_COLOR_RED STYLE_BOLD"PLEASE WRITE OR SAVE THESE DETAILS SAFELY AS YOU WILL NOT BE ABLE TO RETRIEVE THEM LATER!"ANSI_COLOR_RESET STYLE_NO_BOLD"\nTo know more about the recovery procedure, read the general help.\n");
    printf(ANSI_COLOR_YELLOW STYLE_BOLD"\nMagic Code: %08d",mcode);
    printf("\nMagic Password: %.20s\n",pass);
    printf(ANSI_COLOR_RESET STYLE_NO_BOLD"\nIf you ever lose or need to generate a new pair of Magic Code and Magic Password you will need to create a new private key (which will render your previous setups unusable)\n\n");

    memset (pass, 0, 20);
    memset (rands,0, 20);
    memset (key,0, 10);
    free(key);
    free(hmac_d);
    free(rands);
    free(pass);
    free(s);
    //printf("Passfile created successfully!\n");
    return 0;
}

//Dynamic Truncation and OTP Calculation. Returns a [dig] long OTP (int)
int dyn_trun(unsigned char* hmac_d,int dig){
    int hotp=0;
    uint8_t Byte=0;
    uint8_t LowNib;
    uint32_t DBC=0;

    //Get Last Byte
    Byte= hmac_d[19];
    //printf ("Last byte: %02X\n",Byte);

    //Extract Lower Nibble of Last Byte (offset)
    LowNib=(Byte & 0x0F);
    //printf ("Lower nibble: %X\nOffset = %d\n",LowNib,LowNib);

    //Get 4 Bytes from HC
    Byte = hmac_d[LowNib];
    DBC = ((DBC ^ Byte) << 8);
    Byte = hmac_d[LowNib+1];
    DBC = ((DBC ^ Byte) << 8);
    Byte = hmac_d[LowNib+2];
    DBC = ((DBC ^ Byte) << 8);
    Byte = hmac_d[LowNib+3];
    DBC = (DBC ^ Byte);
    //printf("DBC1 = %X\n",DBC);

    //Mask out MSB
    DBC = DBC & 0x7FFFFFFF;
    //printf("DBC2 = %X\n",DBC);

    //Get HOTP
    hotp = DBC % (int) (pow(10,dig));
    //printf("HOTP = %d\n",hotp);
    return hotp;
}

//Get counter. If called with flag != 0 then flag is added to counter
int get_counter(uint8_t* counter, int flag){
    unsigned long t;
    char count[11]="";
    char str[25]="";
    char * token=NULL;
    char *s=NULL;

    s=conf_file();
    if (open_r(s,str,25)!=0){
        printf("ERROR: Conf file not found");
        free(s);
        return -1;
    }

    else {
        token = strtok(str,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        token=strtok(NULL,",");
        strncpy(count,token,10);
        count[10]='\0';
        t=strtoul(count,NULL,10);

        //If called with flag!=0, add flag to t
        if (flag!=0){
            t = t+flag;
        }
        for (int i = 8; i--; t >>= 8) {
            counter[i] = t;
        }
    }
free(s);
return 0;
}

//Get counter. If called with flag != 0 then flag is added to counter
int get_counter_pam(pam_handle_t *pamh,uint8_t* counter, int flag){
    unsigned long t;
    char count[11]="";
    char str[25]="";
    char * token=NULL;
    char * s=NULL;

    s=conf_file_pam(pamh);
    if (open_r(s,str,25)!=0){
        printf("ERROR: Conf file not found");
        free(s);
        return -1;
    }

    else {
        token = strtok(str,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        token=strtok(NULL,",");
        strncpy(count,token,10);
        count[10]='\0';
        t=strtoul(count,NULL,10);

        //If called with flag!=0, add flag to t
        if (flag!=0){
            t = t+flag;
        }

        for (int i = 8; i--; t >>= 8) {
            counter[i] = t;
        }

    }
free(s);
return 0;
}

//Read current counter, calculate next valid HOTP code
int current_state(){
    char str[25]="";
    char count[11]="";
    char * token=NULL;
    char * s=NULL;
    int mode,i,code,sudo,su,login,ssh;
    unsigned long t;
    uint8_t counter[8];
    int res=0;
    unsigned char* key = malloc(10);
    if (!key){
        printf("Malloc failure! Exiting...");
        return 1;
    }
    unsigned char* hmac_d = malloc (20);
    if (!hmac_d){
        printf("Malloc failure! Exiting...");
        free(key);
        return 1;
    }
    s=conf_file();
    if (open_r(s,str,25)!=0){
        printf("ERROR: Conf file not found");
        free(key);
        free(s);
        free(hmac_d);
        return 1;
    }
    else {
        token = strtok(str,",");
        if (!token){
            printf ("ERROR: Conf file bad format!\n");
            free(key);
            free(s);
            free(hmac_d);
            return 1;
        }
        mode = atoi(token);
        if (mode==1){//HOTP
            printf ("\nMode of Operation: Counter Based\n");
            //Read counter, parse it and convert to long
            token=strtok(NULL,",");
            strncpy(count,token,10);
            count[10]='\0';
            t=strtoul(count,NULL,10);
            for (int i = 8; i--; t >>= 8) {
                counter[i] = t;
            }

            printf("Counter is: ");
            for (i=0;i<8;i++){
                printf("%d",counter[i]);
            }
            printf("\n");
        }
        else if (mode==2){//TOTP
            //Get TOTP counter
            printf ("\nMode of Operation: Time Based\n");
            t = time(NULL)/30;
            for (int i = 8; i--; t >>= 8) {
                counter[i] = t;
            }
        }
        else {
            printf ("ERROR: Conf file bad format!\n");
            free(s);
            free(key);
            free(hmac_d);
            return 1;
        }

    //Retrieve key
    res=get_key(key);
    if(res==1){
        memset (key, 0, 10);
        free(key);
        free(s);
        free(hmac_d);
        return 1;
    }

    //For HOTP Get HMAC for counter equal 0 (Key Integrity Check Value)
    if (mode==1){
        printf("Integrity Check Value= ");
        for (i=0;i<8;i++){
            counter[i]=0;
        }
        code=hmac_dgst(key,hmac_d,counter,6);
        printf("%06d\n",code);
    }

    //For TOTP print current valid code
    else if (mode==2){
        token=strtok(NULL,",");
        printf("Current Valid Code: ");
        code=hmac_dgst(key,hmac_d,counter,6);
        printf("%d\n",code);
    }

    //Check activated Services
    token=strtok(NULL,",");
    if (!token){
        printf("ERROR: Conf file bad format!\n");
        memset (key, 0, 10);
        free(key);
        free(s);
        free(hmac_d);
        return 1;
    }
    sudo=atoi(token);
    token=strtok(NULL,",");
    if (!token){
        printf("ERROR: Conf file bad format!\n");
        memset (key, 0, 10);
        free(key);
        free(s);
        free(hmac_d);
        return 1;
    }
    su=atoi(token);
    token=strtok(NULL,",");
    if (!token){
        printf("ERROR: Conf file bad format!\n");
        memset (key, 0, 10);
        free(key);
        free(s);
        free(hmac_d);
        return 1;
    }
    login=atoi(token);
    token=strtok(NULL,",");
    if (!token){
        printf("ERROR: Conf file bad format!\n");
        memset (key, 0, 10);
        free(key);
        free(s);
        free(hmac_d);
        return 1;
    }
    ssh=atoi(token);
    printf("Activated Services: ");
    if(sudo==1){
        printf("SUDO");
    }
    if(su==1){
        if(sudo==1){
            printf(", ");
        }
        printf("SU");
    }
    if(login==1){
        if(su==1){
            printf(", ");
        }
        printf("Login");
    }
    if(ssh==1){
        if(login==1){
            printf(", ");
        }
        printf("SSH");
    }
    if (sudo+su+login+ssh==0){
        printf("NONE");
    }
    printf("\n");

    memset (key, 0, 10);
    free(key);
    free(s);
    free(hmac_d);
    return 0;
    }
}

//Increase counter by 1+[resynch]
int inc_counter(int resynch){
    unsigned long t;
    char count[11]="";
    char str[25]="";
    int mode, sudo, su, login,ssh;
    char * token=NULL;
    char * s=NULL;

    s=conf_file();
    if (open_r(s,str,25)!=0){
        printf("ERROR: Conf file not found");
        free(s);
        return -1;
    }

    else {
        token = strtok(str,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        mode=atoi(token);
        token=strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        strncpy(count,token,10);
        count[10]='\0';
        t=strtoul(count,NULL,10);
        t+=1+resynch;
        token=strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        sudo=atoi(token);
        token=strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        su=atoi(token);
        token=strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        login=atoi(token);
        token=strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        ssh=atoi(token);

        snprintf(str,25,"%d,%lu,%d,%d,%d,%d",mode,t,sudo,su,login,ssh);
        if (open_w(s,str)!=0){
            printf("ERROR: Not able to write to conf file\n");
            free(s);
            return -1;
        }
    }
free(s);
return 0;
}

//Increase counter by 1+[resynch]
int inc_counter_pam(pam_handle_t *pamh,int resynch){
    unsigned long t;
    char count[11]="";
    char str[25]="";
    int mode, sudo, su, login,ssh;
    char * token=NULL;
    char * s=NULL;

    s=conf_file_pam(pamh);
    if (open_r(s,str,25)!=0){
        printf("ERROR: Conf file not found");
        free(s);
        return -1;
    }

    else {
        token = strtok(str,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        mode=atoi(token);
        token=strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        strncpy(count,token,10);
        count[10]='\0';
        t=strtoul(count,NULL,10);
        t+=1+resynch;
        token=strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        sudo=atoi(token);
        token=strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        su=atoi(token);
        token=strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        login=atoi(token);
        token=strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        ssh=atoi(token);

        snprintf(str,25,"%d,%lu,%d,%d,%d,%d",mode,t,sudo,su,login,ssh);
        if (open_w(s,str)!=0){
            printf("ERROR: Not able to write to conf file\n");
            free(s);
            return -1;
        }
    }
free(s);
return 0;
}

//Creates simple config file using passed params
int create_config_file(char * dir ,int mode, int counter, int sudo, int su, int login, int ssh){
    int flag=0, c;
    char *s=NULL;
    char str[25]="";
    char *ch=malloc(2);
    if (!ch){
        printf("Malloc failure! Exiting...");
        return 1;
    }
    //Verify if config file exists
    s=conf_file();
    if (open_r(s,str,25)==0){
        while (flag==0){
            printf ("\nWARNING!\nAnother config file has been found. Creating a new config file will overwrite this settings and make any previous setups unusable. Are you sure you want to continue? (y/n):\n");
                        fgets(ch,2,stdin);
            while((c = getchar()) != '\n' && c != EOF)
                /* discard extra input*/ ;
            switch(ch[0]){
                case 'y':
                    flag =1;
                    system("clear");
                    printf("\nCreating Config File...\n");
                    snprintf(str,25,"%d,%d,%d,%d,%d,%d", mode,counter,sudo,su,login,ssh);
                    if(open_w(s,str)!=0){
                        printf("Config File creation failure! Exiting...\n");
                        free(ch);
                        free(s);
                        return 1;
                    }
                    printf("Config File created successfully!\n");
                    chmod(s,0600);
                    break;
                case 'Y':
                    flag =1;
                    system("clear");
                    printf("\nCreating Config File...\n");
                    snprintf(str,25,"%d,%d,%d,%d,%d,%d", mode,counter,sudo,su,login,ssh);
                    if(open_w(s,str)!=0){
                        printf("Config File creation failure! Exiting...\n");
                        free(ch);
                        free(s);
                        return 1;
                    }
                    printf("Config File created successfully!\n");
                    chmod(s,0600);
                    break;
                case 'n':
                    system("clear");
                    flag =1;
                    //Do nothing
                    break;
                case 'N':
                    system("clear");
                    flag =1;
                    //Do nothing
                    break;
                default:
                    printf("\nInvalid Option.\n");
            }
        }
    }

    //If config file doesnt exist, create it
    else {
        printf("\nCreating Config File...\n");
        snprintf(str,25,"%d,%d,%d,%d,%d,%d", mode,counter,sudo,su,login,ssh);
        if(open_w(s,str)!=0){
            printf("Config File creation failure! Exiting...\n");
            free(ch);
            free(s);
            return 1;
        }
        printf("Config File created successfully!\n");
        chmod(s,0600);
    }

    free(ch);
    free(s);
    return 0;
}

/*
Verify is certain service is active (0: SSH 1: Sudo, 2: SU, 3: Login)
or mode of operation (4). Returns 0 in case service is active
or mode==counter-based, 1 otherwise. Returns 2 if conf file not
present (2FA not configured for this user account).
Returns -1 in case of error.
*/
int verify_serv(int serv){
    char str[25]="";
    int mode=0, sudo=0, su=0, login=0, ssh=0;
    char * token=NULL;
    char * s=NULL;

    //Validate service request
    if(serv!=1 && serv!=2 && serv!=3 && serv!=4){
        printf("ERROR, unknown service\n");
        return -1;
    }

    s=conf_file();
    if (open_r(s,str,25)!=0){
        printf("ERROR: Conf file not found");
        free(s);
        return 2;
    }
    else {
        token = strtok(str,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        mode = atoi(token);
        token = strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        token = strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        sudo=atoi(token);
        token = strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            return -1;
        }
        su=atoi(token);
        token = strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        login=atoi(token);
        token = strtok(NULL,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            return -1;
        }
        ssh=atoi(token);
    }
    switch (serv){
        case 0:
            if (ssh == 1){
                free(s);
                return 0;
            }
            free(s);
            return 1;
            break;
        case 1:
            if (sudo == 1){
                free(s);
                return 0;
            }
            free(s);
            return 1;
            break;
        case 2:
            if (su == 1){
                free(s);
                return 0;
            }
            free(s);
            return 1;
            break;
        case 3:
            if (login == 1){
                free(s);
                return 0;
            }
            free(s);
            return 1;
            break;
        case 4:
            if (mode == 1){
                free(s);
                return 0;
            }
            free(s);
            return 1;
            break;
        default:
            break;
    }
    free(s);
    return -1;
}

/*
USE THIS FOR LOCAL CHECKS (Works using current user's info)
Test if OTP code provided is correct (Return 0 on success or 1
if code is wrong). Return -1 == ERROR.
*/
int test_code(int try){
    uint8_t counter[8];
    int res,mode,resynch=0;
    unsigned long t;

    unsigned char* key = malloc (10);
    if (!key){
        //printf("Malloc failure! Exiting...");
        return -1;
    }

    unsigned char* hmac_d = malloc (20);
    if (!hmac_d){
        //printf("Malloc failure! Exiting...");
        free(key);
        return -1;
    }

    //Get saved key
    res=get_key(key);
    if(res!=0){
        memset (key, 0, 10);
        free(key);
        free(hmac_d);
        return -1;
    }

    //Verify mode of operation
    mode = is_hotp();

    if (mode ==1){
        //Get HOTP saved counter
        res=get_counter(counter,0);
        if (res!=0){
            memset (key,0,10);
            free(key);
            free(hmac_d);
            return -1;
        }
    }
    else if(mode==2){
        t = time(NULL)/30;
        for (int i = 8; i--; t >>= 8) {
            counter[i] = t;
        }
    }

    //Get next valid hotp value (int)
    res=hmac_dgst(key,hmac_d,counter,6);
    if ((res ^ try) == 0){
        //printf("Valid Code\n");
        res=inc_counter(resynch);
    }
    else{
        if (mode==1){
            //Try with HOTP counter up to +3
            for (resynch=1;resynch<4;resynch++){
                //Get counter + resynch value
                res=get_counter(counter,resynch);
                if (res!=0){
                    memset (key, 0, 10);
                    free(key);
                    free(hmac_d);
                    return -1;
                }
                res=hmac_dgst(key,hmac_d,counter,6);
                if ((res ^ try) == 0){
                    //printf("Valid Code with resynch value %d\n",resynch);
                    break;
                }
                else if (resynch ==3){
                    //printf("Invalid Code! (Counter has not been incremented)\n");
                    memset (key, 0, 10);
                    free(key);
                    free(hmac_d);
                    return 1;
                }
            }
            res=inc_counter(resynch);
            if(res!=0){
                memset (key, 0, 10);
                free(key);
                free(hmac_d);
                return -1;
            }
        }
        else if (mode==2){
            t = (time(NULL)/30)+1;
            for (int i = 8; i--; t >>= 8) {
                counter[i] = t;
            }
            res=hmac_dgst(key,hmac_d,counter,6);
            if ((res ^ try) != 0){
                t = (time(NULL)/30)-1;
                for (int i = 8; i--; t >>= 8) {
                    counter[i] = t;
                }
                res=hmac_dgst(key,hmac_d,counter,6);
                if ((res^try)!=0){
                    memset (key, 0, 10);
                    free(key);
                    free(hmac_d);
                    return 1;
                }
            }
        }
    }
    memset (key, 0, 10);
    free(key);
    free(hmac_d);
    return 0;
}

/*
USE THIS FOR PAM CHECKS
Test if OTP code provided is correct (Return 0 on success or 1
if code is wrong). Return -1 == ERROR.
*/
int test_code_pam(pam_handle_t *pamh,int try){
    uint8_t counter[8];
    int res,mode,resynch=0;
    unsigned long t;

    unsigned char* key = malloc (10);
    if (!key){
        //printf("Malloc failure! Exiting...");
        return -1;
    }

    unsigned char* hmac_d = malloc (20);
    if (!hmac_d){
        //printf("Malloc failure! Exiting...");
        free(key);
        return -1;
    }

    //Get saved key
    res=get_key_pam(pamh,key);
    if(res!=0){
        memset (key, 0, 10);
        free(key);
        free(hmac_d);
        return -1;
    }

    //Verify mode of operation
    mode = is_hotp_pam(pamh);

    if (mode ==1){
        //Get HOTP saved counter
        res=get_counter_pam(pamh,counter,0);
        if (res!=0){
            memset (key,0,10);
            free(key);
            free(hmac_d);
            return -1;
        }
    }
    else if(mode==2){
        t = time(NULL)/30;
        for (int i = 8; i--; t >>= 8) {
            counter[i] = t;
        }
    }

    //Get next valid hotp value (int)
    res=hmac_dgst(key,hmac_d,counter,6);
    if ((res ^ try) == 0){
        //printf("Valid Code\n");
        res=inc_counter_pam(pamh,resynch);
    }
    else{
        if (mode==1){
            //Try with HOTP counter up to +3
            for (resynch=1;resynch<4;resynch++){
                //Get counter + resynch value
                res=get_counter_pam(pamh,counter,resynch);
                if (res!=0){
                    memset (key, 0, 10);
                    free(key);
                    free(hmac_d);
                    return -1;
                }
                res=hmac_dgst(key,hmac_d,counter,6);
                if ((res ^ try) == 0){
                    //printf("Valid Code with resynch value %d\n",resynch);
                    break;
                }
                else if (resynch ==3){
                    //printf("Invalid Code! (Counter has not been incremented)\n");
                    memset (key, 0, 10);
                    free(key);
                    free(hmac_d);
                    return 1;
                }
            }
            res=inc_counter(resynch);
            if(res!=0){
                memset (key, 0, 10);
                free(key);
                free(hmac_d);
                return -1;
            }
        }
        else if (mode==2){
            t = (time(NULL)/30)+1;
            for (int i = 8; i--; t >>= 8) {
                counter[i] = t;
            }
            res=hmac_dgst(key,hmac_d,counter,6);
            if ((res ^ try) != 0){
                t = (time(NULL)/30)-1;
                for (int i = 8; i--; t >>= 8) {
                    counter[i] = t;
                }
                res=hmac_dgst(key,hmac_d,counter,6);
                if ((res^try)!=0){
                    memset (key, 0, 10);
                    free(key);
                    free(hmac_d);
                    return 1;
                }
            }
        }
    }
    memset (key, 0, 10);
    free(key);
    free(hmac_d);
    return 0;
}

//Select Services
int select_services(){
    int sudo =0, su=0, login=0, ssh=0, mode,c;
    char str[25]="";
    char * token=NULL;
    char * s=NULL;

    char *ch=malloc(2);
    if (ch==NULL){
        printf("Malloc failure! Exiting...");
        return 1;
    }

    s=conf_file();
    if (open_r(s,str,25)!=0){
        printf("\nERROR: No config file found. If setting up for the first time select SETUP first\n");
        free(s);
        free(ch);
        return 0;
    }

    else{
        printf("\nSelect Services\n-------------------------------\nActivate for SUDO under this user? (Y/n): ");
        fgets(ch,2,stdin);
        while((c = getchar()) != '\n' && c != EOF)/* discard extra input*/ ;
        switch(ch[0]){
            case 'Y': /*Yes*/
                sudo = 1;
                break;
            case 'y':
                sudo = 1;
                break;
            default: /* No */
                break;
        }

        printf("\nActivate for SU (Switch User) onto this user? (Y/n): ");
        fgets(ch,2,stdin);
        while((c = getchar()) != '\n' && c != EOF)/* discard extra input*/ ;
        switch(ch[0]){
            case 'Y': /*Yes*/
                su = 1;
                break;
            case 'y':
                su = 1;
                break;
            default: /* No */
                break;
        }

        printf("\nActivate for logging onto this user? (Y/n):");
        fgets(ch,2,stdin);
        while((c = getchar()) != '\n' && c != EOF)/* discard extra input*/ ;
        switch(ch[0]){
            case 'Y': /*Yes*/
                login = 1;
                break;
            case 'y':
                login = 1;
                break;
            default: /* No */
                break;
        }

        printf("\nActivate for SSH onto this user? (Y/n):");
        fgets(ch,2,stdin);
        while((c = getchar()) != '\n' && c != EOF)/* discard extra input*/ ;
        switch(ch[0]){
            case 'Y': /*Yes*/
                ssh = 1;
                break;
            case 'y':
                ssh = 1;
                break;
            default: /* No */
                break;
        }

        system("clear");
        printf("\nServices Selected: ");
        if (sudo==1){
            printf("SUDO");
        }
        if (su==1){
            if (sudo==1){
                printf(", ");
            }
            printf("SU");
        }
        if (login==1){
            if (su==1){
                printf(", ");
            }
            printf("Login");
        }
        if (ssh==1){
            if (login==1){
                printf(", ");
            }
            printf("SSH");
        }
        if (login==0 && su==0 && sudo==0 && ssh==0){
            printf("NONE");
        }
        printf("\n");

        //READ FROM FILE AND EDIT
        token = strtok(str,",");
        if (!token){
            printf ("ERROR: Conf file bad format!");
            free(s);
            free(ch);
            return 1;
        }
        mode = atoi(token);
        token=strtok(NULL,",");
        snprintf(str,25,"%d,%s,%d,%d,%d,%d", mode,token,sudo,su,login,ssh);
        if(open_w(s,str)!=0){
            printf("ERROR: Could not write to Config File\n");
            free(ch);
            free(s);
            return 1;
        }
        printf("Configuration chages made successfully!\n");
    }
    free(s);
    free(ch);
    return 0;
}

//Checks if code is Magic Code or not. Returns 0 if yes, 1 if not, -1 if error.
int magic_check(pam_handle_t *pamh, int try){
    int i,code;
    uint8_t counter[8];
    int res=0;
    unsigned char* key = malloc(10);
    if (!key){
        printf("Malloc failure! Exiting...");
        return -1;
    }
    unsigned char* hmac_d = malloc (20);
    if (!hmac_d){
        printf("Malloc failure! Exiting...");
        free(key);
        return -1;
    }
    else {
        //Retrieve key
        res=get_key_pam(pamh,key);
        if(res==1){
            memset (key, 0, 10);
            free(key);
            free(hmac_d);
            return -1;
        }

        //Set counter to 0 (MAGIC CODE == 8-Digit Code with COUNTER==0)
        for (i=0;i<8;i++){
            counter[i]=0;
        }
        code=hmac_dgst(key,hmac_d,counter,8);

        //IF CODE IS MAGIC CODE
        if ((try ^ code)==0){
            memset (key, 0, 10);
            free(key);
            free(hmac_d);
            return 0;
        }

        //ELSE
        else {
            memset (key, 0, 10);
            free(key);
            free(hmac_d);
            return 1;
        }
    }
}

//Checks if code if Magic Pass is correct or not. Returns 0 if yes, 1 if not, -1 if error.
int magic_pass_check(pam_handle_t *pamh, char * try){
    SHA256_CTX context;
    int i=0;
    char * s=NULL;
    char * token=NULL;
    char str[75]="";//pass file should be 73 chars long
    char hash[65]="";
    char salt[9]="";
    unsigned char md [32]="";//For hash in binary
    char hex [3]="";//To transform binary md to hex
    char tryhash [65]="";//For hash of the password tried

    s=pass_file_pam(pamh);
    if (open_r(s,str,75)!=0){
        free(s);
        return -1;
    }
    token = strtok(str,",");
    strcpy(hash,token);
    token = strtok(NULL,",");
    strcpy(salt,token);
    //Initialize SHA256 context
    if(!SHA256_Init(&context)){
        free(s);
    }

    //Update Hash Context sending salt, then pass (try)
    if(!SHA256_Update(&context, (unsigned char*)salt, strlen(salt))){
        free(s);
        memset(try,0,strlen(try));
        return -1;
    }

    if(!SHA256_Update(&context, (unsigned char*)try, strlen(try))){
        free(s);
        memset(try,0,strlen(try));
        return -1;
    }
    //Get hash of salt + password tried
    if(!SHA256_Final(md,&context)){
        free(s);
        memset(try,0,strlen(try));
        return -1;
    }

    for (i=0;i<32;i++){
        snprintf(hex,3,"%02x",md[i]);
        tryhash[i*2]=hex[0];
        tryhash[(i*2)+1]=hex[1];
    }
    tryhash[64]='\0';
    if (strcmp(tryhash,hash)==0){
        free(s);
        memset(try,0,strlen(try));
        return 0;
    }

    free(s);
    memset(try,0,strlen(try));
    return 1;
}
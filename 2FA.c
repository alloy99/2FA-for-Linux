#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define STYLE_BOLD         "\033[1m"
#define STYLE_NO_BOLD      "\033[22m"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <fcntl.h>
#include <math.h>
#include "2fa_lib.h"

void menu(char *ch){
    int c;
    printf("\n-------------------------------\n0)Help and How-to's\n1)Setup for Current User\n2)Key Management\n3)Select Services\n4)Current State\n9)Exit\n-------------------------------\n\nPlease select an option:");
    fgets(ch,2,stdin);
    while((c = getchar()) != '\n' && c != EOF)
        /* discard extra input*/ ;
}

int func0(){
    int c;
    int flag=0;
    char *ch=malloc(2);

    if (ch==NULL){
        printf("Malloc failure! Exiting...");
        return 1;
    }

    char *ch2=malloc(7);

    if (ch2==NULL){
        printf("Malloc failure! Exiting...");
        free(ch);
        return 1;
    }


    while (flag == 0){
        printf("\nHelp Menu\n-------------------------------\n1)General Help\n2)First Time Setup\n3)Security Considerations\n4)About\n9)Go back\n-------------------------------\n\nPlease select an option:");
        fgets(ch,2,stdin);
        while((c = getchar()) != '\n' && c != EOF)/* discard extra input*/ ;
        switch(ch[0]){
            case '1': /*Create New Key*/
                system("clear");
                system("more -d ghelp");
                break;
            case '2': /*View Key*/
                system("clear");
                system("more -d ftsetup");
                break;
            case '3': /*Test Code*/
                system("clear");
                system("more -d secons");
                break;
            case '4': /*Test Code*/
                system("clear");
                system("more -d about");
                break;
            case '9': /*Go Back*/
                system("clear");
                flag=1;
                break;
            default:
                system("clear");
                printf("\nInvalid Option.\n");
        }
    }
    free (ch);
    free (ch2);
    return 0;
}

int func1(){
    FILE * fp,*fpr;
    struct stat st;
    int c, mode,lines=0,real_lines=0,pam_location=0;
    int flag=0;
    int res=0;
    int pamflag=0,pam_unix=0,pam_unix_real_lines=0,pam_jumps_to_deny=0,pam_jumps_to_permit=0;
    size_t len=0;
    char *dddir=NULL;
    char *ddir=NULL;
    char *dir=NULL;
    char *line=NULL;
    char *s=NULL;
    char pam_line_to_write[70]="";
    struct passwd *passwdEnt = getpwuid(getuid());
    char *home = passwdEnt->pw_dir;
    char *ch=malloc(2);
    char ch2[2]="";

    if (ch==NULL){
        printf("Malloc failure! Exiting...");
        return 1;
    }
    dir = malloc (sizeof(home)+16);
    if (dir==NULL){
        printf("Malloc failure! Exiting...");
        free(ch);
        return 1;
    }
    ddir = malloc (sizeof(home)+16);
    if (dir==NULL){
        printf("Malloc failure! Exiting...");
        free(ch);
        free(dir);
        return 1;
    }
    dddir = malloc (sizeof(home)+16);
    if (dir==NULL){
        printf("Malloc failure! Exiting...");
        free(ch);
        free(dir);
        free(ddir);
        return 1;
    }
    strcpy(dir,"\0");
    //Get users home directory
    strcat(dir,home);
    strcat(dir,"/2FA");
    strcpy(ddir,dir);
    strcat(ddir,"/key.k");
    strcpy(dddir,dir);
    strcat(dddir,"/shadow");

    //Verify theres a 2FA directory, otherwise create it
    if (stat(dir, &st)!=0){
        mkdir(dir,0700);
        strcat(dir,"/2FA.conf");
        fp = fopen(dir,"w");
        fclose(fp);
        fp = fopen(ddir,"w");
        fclose(fp);
        fp = fopen(dddir,"w");
        fclose(fp);
        chmod(dir,0600);
        chmod(ddir,0600);
        chmod(dddir,0600);
    }
    while (flag == 0){
        printf("\nSetup:\n-------------------------------\n1)Counter Based\n2)Time Based\n3)System Setup\n9)Go Back\n-------------------------------\n\nPlase select an option:");
        fgets(ch,2,stdin);
        while((c = getchar()) != '\n' && c != EOF)/* discard extra input*/ ;
        switch(ch[0]){
            case '3': /* FT Setup */
                flag=1;
                system("clear");

                //CHECK IF A CONF FILE EXISTS AND IS NOT EMPTY AND THAT A KEY FILE EXISTS AND IS NOT EMPTY, ONLY THEN PROCEED
                s=conf_file();
                if(stat(s,&st)!=0){
                    printf("ERROR: No conf file found. System Setup is only to be run after user setup.\n");
                    free(s);
                    return 0;
                }
                if(st.st_size < 1){
                    printf("ERROR: No user configuration found. System Setup is only to be run after user setup.\n");
                    free(s);
                    return 0;
                }
                s=key_file();
                if(stat(s,&st)!=0){
                    printf("ERROR: No key file found. System Setup is only to be run after key creation.\n");
                    free(s);
                    return 0;
                }
                if(st.st_size < 5){
                    printf("ERROR: No key set. System Setup is only to be run after key creation.\n");
                    free(s);
                    return 0;
                }
                free(s);

                printf("This option will perform the needed actions for a First Time Setup for your Operating System. In case this option fails for any reason, refer to Help for details on how to carry on a First Time Setup for your Operating System manually. At some point during the setup you will need to provide your user password (due to the use of sudo), it however will not be recorded by 2FA. Note that if your user has no permission to execute sudo System Setup will fail.\n\nPress enter to continue.");
                fgets(ch2,1,stdin);
                while((c = getchar()) != '\n' && c != EOF)/* discard extra input*/ ;
                if(stat("/lib/security/pam_unix.so",&st)==0){
                    system("sudo cp pam_2fa.so /lib/security/pam_2fa.so");
                    system("sudo chmod 0644 /lib/security/pam_2fa.so");
                    system("sudo chown root:root /lib/security/pam_2fa.so");
                    printf("pam libray copied to /lib/security/\n");
                }
                else if(stat("/lib/x86_64-linux-gnu/security/pam_unix.so",&st)==0){
                    system("sudo cp pam_2fa.so /lib/x86_64-linux-gnu/security/pam_2fa.so");
                    system("sudo chmod 0644 /lib/x86_64-linux-gnu/security/pam_2fa.so");
                    system("sudo chown root:root /lib/x86_64-linux-gnu/security/pam_2fa.so");
                    printf("pam libray copied to /lib/x86_64-linux-gnu/security/\n");
                }
                else if(stat("/lib64/security/pam_unix.so",&st)==0){
                    system("sudo cp pam_2fa.so /lib64/security/pam_2fa.so");
                    system("sudo chmod 0644 /lib64/security/pam_2fa.so");
                    system("sudo chown root:root /lib64/security/pam_2fa.so");
                    printf("pam libray copied to /lib64/security/\n");
                }
                else{
                    printf("ERROR: Could not find pam library directory!\nSystem Setup FAILED!\n");
                    return 0;
                }
                printf("\nLooking for common-auth pam file...\n");
                if(stat("/etc/pam.conf/common-auth",&st)!=0){
                    printf("Not in /etc/pam.conf. Looking in /etc/pam.d...\n");
                    if(stat("/etc/pam.d/common-auth",&st)!=0){
                        printf("Not in /etc/pam.d either.\nERROR: Can't find common-auth pam file!\nSystem Setup FAILED!\n");
                        return 0;
                    }
                    else{
                        printf("common-auth found on /etc/pam.d!\n");
                        pam_location=1;
                    }
                }
                else{
                    printf("common-auth found on /etc/pam.conf!\n");
                    pam_location=2;
                }
                printf("Analyzing common-auth\n");
                if(pam_location==1){
                    fp=fopen("/etc/pam.d/common-auth","r");
                    if (!fp){
                        printf("Error opening common-auth.\nSystem Setup FAILED!\n");
                        return 0;
                    }
                }
                else if(pam_location==2){
                    fp=fopen("/etc/pam.conf/common-auth","r");
                    if (!fp){
                        printf("Error opening common-auth.\nSystem Setup FAILED!\n");
                        return 0;
                    }
                }
                else{
                        printf("Error opening common-auth.\nSystem Setup FAILED!\n");
                        return 0;
                }
                while (getline(&line, &len, fp) != -1) {
                    lines++;
                    if(line[0]!='#'){
                        real_lines++;
                        if(strcmp(line,"auth\t[success=1 default=ignore]\tpam_unix.so nullok_secure\n")==0){
                            printf("pam_unix found at line %d\n",lines);
                            pamflag++;
                            pam_unix_real_lines=real_lines;
                            pam_unix=lines;
                        }
                        if(strcmp(line,"auth\trequisite\t\t\tpam_deny.so\n")==0){
                            printf("pam_deny found at line %d\n",lines);
                            pamflag++;
                            pam_jumps_to_deny=real_lines-pam_unix_real_lines;
                            printf("PAM jumps to deny: %d\n",pam_jumps_to_deny);
                        }
                        if(strcmp(line,"auth\trequired\t\t\tpam_permit.so\n")==0){
                            printf("pam_permit found at line %d\n",lines);
                            pamflag++;
                            pam_jumps_to_permit=real_lines-pam_unix_real_lines;
                            printf("PAM jumps to permit: %d\n",pam_jumps_to_permit);
                        }
                    }
                }
                if(pamflag!=3 || pam_jumps_to_permit<0 || pam_jumps_to_deny<0 || pam_jumps_to_deny>99 || pam_jumps_to_permit>99 || real_lines>4){
                    printf("ERROR: common-auth file format not recognized.\nSystem Setup FAILED!\n");
                    return 0;
                }
                snprintf(pam_line_to_write,70,"auth\t[success=%d ignore=ignore perm_denied=%d default=bad]\tpam_2fa.so\n",pam_jumps_to_permit,pam_jumps_to_deny);
                printf("line to write to common-auth: %s",pam_line_to_write);
                printf("Editing common-auth file and creating a backup (backup_common-auth).\n");
                if (pam_location==1){
                    fclose(fp);
                    system("sudo touch /new_common-auth");
                    fpr=fopen("new_common-auth","w");
                    if(!fpr){
                        printf("Error opening common-auth.\nSystem Setup FAILED!\n");
                        free(line);
                        return 0;
                    }
                    fp=fopen("/etc/pam.d/common-auth","r");
                    if(!fp){
                        fclose(fpr);
                        printf("Error opening common-auth.\nSystem Setup FAILED!\n");
                        free(line);
                        return 0;
                    }
                }
                else{
                    fclose(fp);
                    system("sudo touch /new_common-auth");
                    fpr=fopen("new_common-auth","w");
                    if(!fpr){
                        printf("Error opening common-auth.\nSystem Setup FAILED!\n");
                        free(line);
                        return 0;
                    }
                    fp=fopen("/etc/pam.conf/common-auth","r");
                    if(!fp){
                        fclose(fpr);
                        printf("Error opening common-auth.\nSystem Setup FAILED!\n");
                        free(line);
                        return 0;
                    }
                }
                lines = 0;
                //Begin re-writing common-auth
                while (getline(&line, &len, fp) != -1) {
                    lines++;
                    if (lines == pam_unix){
                        fprintf(fpr,"%s",pam_line_to_write);
                    }
                    fprintf(fpr,"%s",line);
                }
                fclose(fp);
                fclose(fpr);
                //File Written, now make a backup of original common-auth and replace original with ours
                if (pam_location==1){
                    system("sudo cp /etc/pam.d/common-auth /etc/pam.d/backup_common-auth");
                    printf("backup_common-auth created!\n");
                    system("sudo mv new_common-auth /etc/pam.d/common-auth");
                    system("sudo chmod 0644 /etc/pam.d/common-auth");
                    system("sudo chown root:root /etc/pam.d/common-auth");
                }
                else{
                    system("sudo cp /etc/pam.conf/common-auth /etc/pam.conf/backup_common-auth");
                    printf("backup_common-auth created!\n");
                    system("sudo mv new_common-auth /etc/pam.conf/common-auth");
                    system("sudo chmod 0644 /etc/pam.conf/common-auth");
                    system("sudo chown root:root /etc/pam.conf/common-auth");
                }
                printf("common-auth file edited!\n");

                //SSH
                if(stat("/etc/ssh/sshd_config",&st)==0){
                    printf("Open SSH Server config file found!\nCreating backup (backup_sshd_config).\n");
                    printf("Modifying sshd_config to accept Challenge-Response Authentication.\n");
                    system("touch new-sshd_config");
                    system("sudo cp /etc/ssh/sshd_config /etc/ssh/backup_sshd_config");
                    fp=fopen("/etc/ssh/sshd_config","r");
                    fpr=fopen("new-sshd_config","w");

                    while (getline(&line, &len, fp) != -1) {
                        if (strcmp("ChallengeResponseAuthentication no\n",line)==0){
                            fprintf(fpr,"ChallengeResponseAuthentication yes\n");
                        }
                        else{
                            fprintf(fpr,"%s",line);
                        }
                    }
                    fclose(fp);
                    fclose(fpr);
                    free(line);
                    system("sudo mv new-sshd_config /etc/ssh/sshd_config");
                    system("sudo chmod 0644 /etc/ssh/sshd_config");
                    system("sudo chown root:root /etc/ssh/sshd_config");
                    printf("sshd_config modified!");
                }
                else{
                    free(line);
                    printf("\nWARNING: No Open SSH Server config file found. If this is an error, read the help files to setup SSH Server manually.\n");
                }
                printf("\n\nSystem Setup Finished!\n");
                break;
            case '1': /* Counter Based */
                mode=1;
                flag=1;
                system("clear");
                printf("\nSelected mode of operation: Counter Based\n");
                res=create_config_file(dir,mode,1,0,0,0,0);
                if (res!=0){
                    free(ch);
                    free(dir);
                    free(ddir);
                    free(dddir);
                    return 1;
                }
                break;
            case '2': /* Time Based */
                mode=2;
                flag=1;
                system("clear");
                printf("\nSelected mode of operation: Time Based\n");
                printf("Please make sure this machine and your Google Authenticator App share the same time\n");
                res=create_config_file(dir,mode,0,0,0,0,0);
                if (res!=0){
                    free(ch);
                    free(dir);
                    free(ddir);
                    free(dddir);
                    return 1;
                }
                break;
            case '9': /*Go Back*/
                flag=1;
                system("clear");
                break;
            default:
                system("clear");
                printf("\nInvalid Option\n");
        }
    }
    free(ch);
    free(dir);
    free(ddir);
    free(dddir);
    return 0;
}

int func2(){
    int c,try;
    int flag=0;
    int res=0;
    char *ch=malloc(2);

    if (ch==NULL){
        printf("Malloc failure! Exiting...");
        return 1;
    }

    char *ch2=malloc(7);

    if (ch2==NULL){
        printf("Malloc failure! Exiting...");
        free(ch);
        return 1;
    }


    while (flag == 0){
        printf("\nKey Management\n-------------------------------\n1)Create New Key\n2)View Key\n3)Test Code\n9)Go back\n-------------------------------\n\nPlease select an option:");
        fgets(ch,2,stdin);
        while((c = getchar()) != '\n' && c != EOF)/* discard extra input*/ ;
        switch(ch[0]){
            case '1': /*Create New Key*/
                res=create_key();
                if (res!=0){
                    return 1;
                }
                break;
            case '2': /*View Key*/
                res=view_key();
                if (res!=0){
                    return 1;
                }
                break;
            case '3': /*Test Code*/
                printf("\nWarning: This will increase the counter for counter-mode\n");
                printf("Code to test (Remember codes are 6 digits long): ");
                fgets(ch2,7,stdin);
                ch2[6]='\0';
                while((c = getchar()) != '\n' && c != EOF)/* discard extra input*/ ;
                try=atoi(ch2);
                res=test_code(try);
                if (res==-1){
                    return 1;
                }
                if (res==1){
                    system("clear");
                    printf("\nThe code %s is INVALID!\n",ch2);
                }
                if (res==0){
                    system("clear");
                    printf("\nThe code %s is VALID!\n\n",ch2);
                }
                break;
            case '9': /*Go Back*/
                system("clear");
                flag=1;
                break;
            default:
                system("clear");
                printf("\nInvalid Option.\n");
        }
    }
    free (ch);
    free (ch2);
    return 0;
}

int func3(){
    int res;

    res=select_services();
    if(res!=0){
        return 1;
    }

    return 0;
}

int func4(){
    int res;

    res=current_state();
    if (res!=0){
        return 1;
    }

    return 0;
}

int main (){
    char *ch=malloc(2);
    int flag = 0;
    int res=0;
    if (ch==NULL){
        printf("Malloc failure! Exiting...");
        return 1;
    }
    file_lock_init();
    system("clear");
    while (flag == 0){

        printf("\n +-+-+-+-+-+-+-+-+\n+|"ANSI_COLOR_YELLOW STYLE_BOLD "2"ANSI_COLOR_RESET STYLE_NO_BOLD "|"ANSI_COLOR_YELLOW STYLE_BOLD"F"ANSI_COLOR_RESET STYLE_NO_BOLD"|"ANSI_COLOR_YELLOW STYLE_BOLD"A"ANSI_COLOR_RESET STYLE_NO_BOLD"| |"ANSI_COLOR_YELLOW STYLE_BOLD"M"ANSI_COLOR_RESET STYLE_NO_BOLD"|"ANSI_COLOR_YELLOW STYLE_BOLD"E"ANSI_COLOR_RESET STYLE_NO_BOLD"|"ANSI_COLOR_YELLOW STYLE_BOLD"N"ANSI_COLOR_RESET STYLE_NO_BOLD"|"ANSI_COLOR_YELLOW STYLE_BOLD"U"ANSI_COLOR_RESET STYLE_NO_BOLD"|+\n +-+-+-+-+-+-+-+-+\n");
        menu(ch);

        switch(ch[0]){
            case '1': //Setup
                system("clear");
                res=func1();
                if (res!=0){
                    return 1;
                }
                break;
            case '2': //Key Management
                system("clear");
                res=func2();
                if (res!=0){
                    return 1;
                }
                break;
            case '3': //Configure
                system("clear");
                res=func3();
                if (res!=0){
                    return 1;
                }
                break;
            case '4': //Current State
                system("clear");
                res=func4();
                if (res!=0){
                    return 1;
                }
                break;
            case '0': //Help
                system("clear");
                func0();
                break;
            case '9': //exit
                flag=1;
                break;
            default:
                system("clear");
                printf("\nInvalid Option.\n");
        }
    }
    free(ch);
    return 0;
}
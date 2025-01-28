/* Define which PAM interfaces we provide */
#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

/* Include PAM headers */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <math.h>
#include "2fa_lib.h"

/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {

    int ret,try;
    char * service=NULL;
    char * user=NULL;
    struct pam_response *resp = NULL;
    struct pam_response *resp2 = NULL;
    struct pam_conv *conv;

    void file_lock_init();
    ret=pam_get_item(pamh,PAM_SERVICE,(const void **)&service);
    if (ret!=PAM_SUCCESS){
        return PAM_AUTH_ERR;
    }
    //printf("Service: %s\n",service);
    //Verify service is activated by 2FA
    if(strcmp(service,"sudo")==0){
        ret=verify_serv(1);
        if (ret==-1){
            free(resp->resp);
            free(resp);
            return PAM_AUTH_ERR;
        }
        if(ret==1 || ret==2){
            return PAM_IGNORE;
        }
        const struct pam_message msg = { .msg_style = PAM_PROMPT_ECHO_OFF,.msg = "Verification Code: " };
        const struct pam_message *msgs = &msg;

        ret = pam_get_item(pamh, PAM_CONV, (void *)&conv);
        if (ret != PAM_SUCCESS) {
            return PAM_AUTH_ERR;
        }
        ret = conv->conv(1, &msgs, &resp, conv->appdata_ptr);
        if (ret != PAM_SUCCESS || resp == NULL || resp->resp == NULL || *resp->resp == '\000') {
            free(resp->resp);
            free(resp);
            return PAM_AUTH_ERR;
        }

        try=atoi(resp->resp);
        free(resp->resp);
        free(resp);

        //CHECK IF CODE IS MAGIC CODE
        ret=magic_check(pamh,try);
        if (ret==0){
            //IS MAGIC CODE! ASK FOR MAGIC PASSWORD
            const struct pam_message msg2 = { .msg_style = PAM_PROMPT_ECHO_OFF,.msg = "Password: " };
            const struct pam_message *msgs2 = &msg2;
            ret = conv->conv(1, &msgs2, &resp2, conv->appdata_ptr);
            if (ret != PAM_SUCCESS || resp2 == NULL || resp2->resp == NULL || *resp2->resp == '\000') {
                free(resp2->resp);
                free(resp2);
                return PAM_AUTH_ERR;
            }
            ret=magic_pass_check(pamh, resp2->resp);
            free(resp2->resp);
            free(resp2);
            //If correct send success (this will cause pam stack to jump to pam_permit), otherwise send PAM_PERM_DENIED
            if (ret==0){
                return PAM_SUCCESS;
            }
            else{
                sleep(2);
                return PAM_PERM_DENIED;
            }
        }
        else if (ret==1){
            //TEST CODE NORMALLY
            if (test_code_pam(pamh,try)!=0){
                return PAM_AUTH_ERR;
            }
        }
        else if (ret==-1){
            return PAM_AUTH_ERR;
        }
    }
    else if (strcmp(service,"su")==0){
        ret=pam_get_item(pamh,PAM_USER,(const void **)&user);
        if (ret!=PAM_SUCCESS){
            return PAM_AUTH_ERR;
        }
        //check if 2FA is activated for SU to user
        ret=su_user(user);
        //If config file doesnt exist we assume no 2FA configuration exist for this user
        if (ret==1){
            return PAM_IGNORE;
        }
        if (ret==-1){
            return PAM_AUTH_ERR;
        }
        const struct pam_message msg = { .msg_style = PAM_PROMPT_ECHO_OFF,.msg = "Verification Code: " };
        const struct pam_message *msgs = &msg;

        ret = pam_get_item(pamh, PAM_CONV, (void *)&conv);
        if (ret != PAM_SUCCESS) {
            return PAM_AUTH_ERR;
        }
        ret = conv->conv(1, &msgs, &resp, conv->appdata_ptr);
        if (ret != PAM_SUCCESS || resp == NULL || resp->resp == NULL || *resp->resp == '\000') {
            free(resp->resp);
            free(resp);
            return PAM_AUTH_ERR;
        }

        try=atoi(resp->resp);
        free(resp->resp);
        free(resp);

        //CHECK IF CODE IS MAGIC CODE
        ret=magic_check(pamh,try);
        if (ret==0){
            //IS MAGIC CODE! ASK FOR MAGIC PASSWORD
            const struct pam_message msg2 = { .msg_style = PAM_PROMPT_ECHO_OFF,.msg = "Password: " };
            const struct pam_message *msgs2 = &msg2;
            ret = conv->conv(1, &msgs2, &resp2, conv->appdata_ptr);
            if (ret != PAM_SUCCESS || resp2 == NULL || resp2->resp == NULL || *resp2->resp == '\000') {
                free(resp2->resp);
                free(resp2);
                return PAM_AUTH_ERR;
            }
            ret=magic_pass_check(pamh, resp2->resp);
            free(resp2->resp);
            free(resp2);
            //If correct send success (this will cause pam stack to jump to pam_permit), otherwise send PAM_PERM_DENIED
            if (ret==0){
                return PAM_SUCCESS;
            }
            else{
                sleep(2);
                return PAM_PERM_DENIED;
            }
        }
        else if (ret==1){
            //TEST CODE NORMALLY
            if (test_code_pam(pamh,try)!=0){
                return PAM_AUTH_ERR;
            }
        }
        else if (ret==-1){
            return PAM_AUTH_ERR;
        }
    }
    else if (strcmp(service,"lightdm")==0 || strcmp(service,"login")==0 || strcmp(service,"lightdm-greeter")==0){
        ret=pam_get_item(pamh,PAM_USER,(const void **)&user);
        if (ret!=PAM_SUCCESS){
            return PAM_AUTH_ERR;
        }
        //check if 2FA is activated for login to user
        ret=login_user(user);
        if (ret==1){
            return PAM_IGNORE;
        }
        if (ret==-1){
            return PAM_AUTH_ERR;
        }

        const struct pam_message msg = { .msg_style = PAM_PROMPT_ECHO_OFF,.msg = "Verification Code: " };
        const struct pam_message *msgs = &msg;

        ret = pam_get_item(pamh, PAM_CONV, (void *)&conv);
        if (ret != PAM_SUCCESS) {
            return PAM_AUTH_ERR;
        }
        ret = conv->conv(1, &msgs, &resp, conv->appdata_ptr);
        if (ret != PAM_SUCCESS || resp == NULL || resp->resp == NULL || *resp->resp == '\000') {
            free(resp->resp);
            free(resp);
            return PAM_AUTH_ERR;
        }
        try=atoi(resp->resp);
        free (resp->resp);
        free (resp);

        //CHECK IF CODE IS MAGIC CODE
        ret=magic_check(pamh,try);
        if (ret==0){
            //IS MAGIC CODE! ASK FOR MAGIC PASSWORD
            const struct pam_message msg2 = { .msg_style = PAM_PROMPT_ECHO_OFF,.msg = "Password: " };
            const struct pam_message *msgs2 = &msg2;
            ret = conv->conv(1, &msgs2, &resp2, conv->appdata_ptr);
            if (ret != PAM_SUCCESS || resp2 == NULL || resp2->resp == NULL || *resp2->resp == '\000') {
                free(resp2->resp);
                free(resp2);
                return PAM_AUTH_ERR;
            }
            ret=magic_pass_check(pamh, resp2->resp);
            free(resp2->resp);
            free(resp2);
            //If correct send success (this will cause pam stack to jump to pam_permit), otherwise send PAM_PERM_DENIED
            if (ret==0){
                return PAM_SUCCESS;
            }
            else{
                sleep(2);
                return PAM_PERM_DENIED;
            }
        }
        else if (ret==1){
            //TEST CODE NORMALLY
            if (test_code_pam(pamh,try)!=0){
                return PAM_AUTH_ERR;
            }
        }
        else if (ret==-1){
            return PAM_AUTH_ERR;
        }
    }
    else if (strcmp(service,"sshd")==0){
        ret=pam_get_item(pamh,PAM_USER,(const void **)&user);
        if (ret!=PAM_SUCCESS){
            return PAM_AUTH_ERR;
        }

        const struct pam_message msg = { .msg_style = PAM_PROMPT_ECHO_OFF,.msg = "Verification Code: " };
        const struct pam_message *msgs = &msg;

        ret = pam_get_item(pamh, PAM_CONV, (void *)&conv);
        if (ret != PAM_SUCCESS) {
            return PAM_AUTH_ERR;
        }
        ret = conv->conv(1, &msgs, &resp, conv->appdata_ptr);
        if (ret != PAM_SUCCESS || resp == NULL || resp->resp == NULL || *resp->resp == '\000') {
            free(resp->resp);
            free(resp);
            return PAM_AUTH_ERR;
        }

        //check if 2FA is activated for login to user
        ret=ssh_user(user);
        if (ret==1){
            return PAM_IGNORE;
        }
        if (ret==-1){
            return PAM_AUTH_ERR;
        }

        try=atoi(resp->resp);
        free (resp->resp);
        free (resp);

        //CHECK IF CODE IS MAGIC CODE
        ret=magic_check(pamh,try);
        if (ret==0){
            //IS MAGIC CODE! ASK FOR MAGIC PASSWORD
            const struct pam_message msg2 = { .msg_style = PAM_PROMPT_ECHO_OFF,.msg = "Password: " };
            const struct pam_message *msgs2 = &msg2;
            ret = conv->conv(1, &msgs2, &resp2, conv->appdata_ptr);
            if (ret != PAM_SUCCESS || resp2 == NULL || resp2->resp == NULL || *resp2->resp == '\000') {
                free(resp2->resp);
                free(resp2);
                return PAM_AUTH_ERR;
            }
            ret=magic_pass_check(pamh, resp2->resp);
            free(resp2->resp);
            free(resp2);
            //If correct send success (this will cause pam stack to jump to pam_permit), otherwise send PAM_PERM_DENIED
            if (ret==0){
                return PAM_SUCCESS;
            }
            else{
                sleep(2);
                return PAM_PERM_DENIED;
            }
        }
        else if (ret==1){
            //TEST CODE NORMALLY
            if (test_code_pam(pamh,try)!=0){
                return PAM_AUTH_ERR;
            }
        }
        else if (ret==-1){
            return PAM_AUTH_ERR;
        }
    }

//If codes are correct, send ignore.
    return PAM_IGNORE;
  }

/*NOT USED*/

  /* PAM entry point for session creation */
  int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
          return(PAM_IGNORE);
  }
  /* PAM entry point for session cleanup */
  int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
          return(PAM_IGNORE);
  }
  /* PAM entry point for accounting */
  int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
          return(PAM_IGNORE);
  }
  /* PAM entry point for setting user credentials (that is, to actually
     establish the authenticated user's credentials to the service provider)
   */
  int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
          return(PAM_IGNORE);
  }
  /* PAM entry point for authentication token (password) changes */
  int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
          return(PAM_IGNORE);
  }

FLAGS= -Wall -m64 -fPIC -DPIC
LIBS= -lcrypto -lpam -lm

OBJECT= 2fa_lib
PROGRAM = 2FA
PAM = pam_2fa

all: $(OBJECT) $(PROGRAM) $(PAM)

$(OBJECT): $(OBJECT).c
	gcc $(FLAGS) -o $(OBJECT).o -c $(OBJECT).c $(LIBS)

$(PROGRAM): $(PROGRAM).c $(OBJECT).o
	gcc $(FLAGS) $(PROGRAM).c $(OBJECT).o -o 2FA $(LIBS)

$(PAM): $(PAM).c $(OBJECT).o
	gcc $(FLAGS) -shared -rdynamic -o $(PAM).so $(PAM).c $(OBJECT).o $(LIBS)


clean:
	$(RM) $(OBJECT).o $(PROGRAM) $(PAM).so *~

#include <stdio.h>
#include <string.h>
#include <unistd.h>

// send recv, communcation a traver des socketon
// on wait un mesg, genre comme irc
// puis en fonction du mesg on exec 
int main(void) {
  char *arg[] = {"/bin/companion", NULL};
  execvp(arg[0], arg);
  return 0;
}

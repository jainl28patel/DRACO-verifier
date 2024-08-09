#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

char** parseSet(char *str) {
  char **result = NULL;
  char *nextString;
  char *c = str;
  int count = 1;

  // Count how many items will be extracted
  while (*c) {
    if (*c == '{') {
      str = c + 1;
    } else if (*c == ',') {
      count++;
    }
    c++;
  }

  // Allocate 1 more to terminate result
  count++;

  result = malloc(sizeof(char *) * (count + 1));
  if (!result) {
    fprintf(stderr, "Malloc failed with a total of %d characters", count + 1);
    abort();
  }

  nextString = strtok(str, ",");
  size_t idx = 0;
  while (nextString != NULL) {
    printf("Now processing %s\n", nextString);
    if (strchr(nextString, '}') != NULL) {
      nextString[strlen(nextString) - 1] = '\0';
    }

    *(result + idx) = strdup(nextString);
    idx++;
    nextString = strtok(NULL, ",");

    while (nextString && *nextString == ' ') {
      nextString++;
    }
  }
  assert(idx == count - 1);
  *(result + idx) = NULL;

  return result;
}



int main(int argc, char** argv) {
  int c;
  char *directory = NULL;
  char contents[100] = "";
  FILE *fp;
  char buff[256];
  while ((c = getopt(argc, argv, "d:")) != -1) {
    switch (c) {
      case 'd':
        directory = optarg;
        break;
      case '?':
        fprintf(stderr,
                "Unknown option character `\\x%x'.\n",
                optopt);
      default:
        abort();
    }
  }
  
  // strcat(directory, "klee-last/verification");
  fp = fopen(directory, "r");
  while (fgets(buff, sizeof(buff), fp)) {
    strcat(contents, buff);
  }
  fclose(fp);

  char **mySet = parseSet(contents);
  char **current = mySet;

  while (*current) {
    printf("Got back '%s'\n", *current);
    current++;
  }

  free(mySet);
  return 0;
}
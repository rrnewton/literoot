// dlopen every shared library named in a list, then exit.
//
// usage: dlopen_many <list-file>
//
// <list-file> holds one library per line (a path, or a name the dynamic
// loader searches for); blank lines and lines starting with '#' are
// skipped; a trailing carriage return is dropped, and a line longer than
// 4094 bytes is refused. Each is opened with RTLD_NOW | RTLD_LOCAL and
// kept open.
// Prints "loaded=<n> listed=<m>" and exits 0 only if every listed
// library loaded.
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: dlopen_many <list-file>\n");
    return 2;
  }
  FILE *list = fopen(argv[1], "r");
  if (!list) {
    perror("dlopen_many: open list");
    return 2;
  }
  char line[4096];
  long listed = 0, loaded = 0;
  while (fgets(line, sizeof line, list)) {
    size_t len = strcspn(line, "\n");
    if (line[len] != '\n' && !feof(list)) {
      fprintf(stderr, "dlopen_many: a line is longer than %zu bytes\n", sizeof line - 2);
      return 2;
    }
    line[len] = '\0';
    if (len > 0 && line[len - 1] == '\r') {
      line[len - 1] = '\0';
    }
    if (line[0] == '\0' || line[0] == '#') {
      continue;
    }
    listed++;
    if (dlopen(line, RTLD_NOW | RTLD_LOCAL)) {
      loaded++;
    } else {
      fprintf(stderr, "dlopen_many: %s\n", dlerror());
    }
  }
  fclose(list);
  printf("loaded=%ld listed=%ld\n", loaded, listed);
  return loaded == listed && listed > 0 ? 0 : 1;
}

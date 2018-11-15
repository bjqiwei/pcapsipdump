#ifndef BSD
  #ifdef USE_BSD_STRING_H
    #include <bsd/string.h>
  #else
    #define strlcpy strncpy
  #endif
#endif

// equivalent of "mkdir -p"
int mkdir_p(const char *path, mode_t mode);

int opts_sanity_check_d(char **opt_fntemplate);

size_t expand_dir_template(char *s, size_t max, const char *format,
                           const char *from,
                           const char *to,
                           const char *callid,
                           const time_t t);

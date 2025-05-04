
#ifndef ENV_HPP
#define ENV_HPP

#include <libpq-fe.h>

typedef struct {
    PGconn* conn = NULL;
} serverenv;

#endif

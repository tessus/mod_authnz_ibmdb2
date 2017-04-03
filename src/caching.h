/*
  +----------------------------------------------------------------------+
  | caching: function prototypes                                         |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2015 Helmut K. C. Tessarek                        |
  +----------------------------------------------------------------------+
  | Licensed under the Apache License, Version 2.0 (the "License"); you  |
  | may not use this file except in compliance with the License. You may |
  | obtain a copy of the License at                                      |
  | http://www.apache.org/licenses/LICENSE-2.0                           |
  |                                                                      |
  | Unless required by applicable law or agreed to in writing, software  |
  | distributed under the License is distributed on an "AS IS" BASIS,    |
  | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or      |
  | implied. See the License for the specific language governing         |
  | permissions and limitations under the License.                       |
  +----------------------------------------------------------------------+
  | Author: Helmut K. C. Tessarek                                        |
  +----------------------------------------------------------------------+
  | Website: http://tessus.github.io/mod_authnz_ibmdb2                   |
  +----------------------------------------------------------------------+
*/

#ifndef CACHING_H
#define CACHING_H

#include "mod_authnz_ibmdb2.h"

typedef struct {
        char   password[MAX_PWD_LENGTH];
        apr_time_t timestamp;
} cached_password_timestamp;

typedef struct {
        int    numgrps;
        apr_time_t timestamp;
} cached_group_timestamp;


int write_cache( request_rec *r, const char *user, const char *password, authn_ibmdb2_config_t *m );
char *read_cache( request_rec *r, const char *user, authn_ibmdb2_config_t *m );
int write_group_cache( request_rec *r, const char *user, const char **grplist, authn_ibmdb2_config_t *m );
char **read_group_cache( request_rec *r, const char *user, authn_ibmdb2_config_t *m );

#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */

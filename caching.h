/*
  +----------------------------------------------------------------------+
  | caching: functions for caching mechanism                             |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2007 Helmut K. C. Tessarek                        |
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
  | Website: http://mod-auth-ibmdb2.sourceforge.net                      |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef CACHING_H
#define CACHING_H

#include <gdbm.h>

static int write_cache( request_rec *r, const char *user, const char *password, authn_ibmdb2_config_t *m );
static char *read_cache( request_rec *r, const char *user, authn_ibmdb2_config_t *m );
static int write_group_cache( request_rec *r, const char *user, const char **grplist, authn_ibmdb2_config_t *m );
static char **read_group_cache( request_rec *r, const char *user, authn_ibmdb2_config_t *m );

/*
	function to store the user credentials in the local cache, so that subsequent
	http requests can validate the user directly from local cache without the need
	to query the backend db2 database.
*/

/* {{{ static int write_cache( request_rec *r, const char *user, const char *password, authn_ibmdb2_config_t *m )
*/
static int write_cache( request_rec *r, const char *user, const char *password, authn_ibmdb2_config_t *m )
{
	char errmsg[MAXERRLEN];

	char *my_user = (char *)user;
	datum datum_user = { my_user, (strlen( my_user )+1) };

	cached_password_timestamp cpt;

	datum datum_value;
	GDBM_FILE gdbm;

	char *my_password = (char *)password;
	strcpy(cpt.password, my_password);

	if ( !(time(&(cpt.timestamp))) )
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "unable to determine current time (write cache)");
		LOG_ERROR( errmsg );
		return( 1 );
	}

	datum_value.dptr = (void *)&cpt;
	datum_value.dsize = sizeof(cpt);

	gdbm = gdbm_open( m->ibmdb2cachefile, 0, GDBM_WRCREAT, 00664, NULL );

	if ( gdbm != NULL )
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "storing user [%s] and pass [%s] in cache", my_user, my_password);
		LOG_DBG( errmsg );

		if( gdbm_store( gdbm, datum_user, datum_value, GDBM_REPLACE ) != 0 )
		{
			errmsg[0] = '\0';
			sprintf( errmsg, "unable to store user [%s] in cache", my_user);
			LOG_DBG( errmsg );
		}

		gdbm_close( gdbm );
	}
	else
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "could not open cachefile [%s] for writing", m->ibmdb2cachefile );
		LOG_ERROR( errmsg );
	}

	return( 0 );
}
/* }}} */

/*
	function to check in the local cache to validate user, otherwise
	we need to query the backend db2 database.
*/

/* {{{ static char *read_cache( request_rec *r, const char *user, authn_ibmdb2_config_t *m )
*/
static char *read_cache( request_rec *r, const char *user, authn_ibmdb2_config_t *m )
{
	char errmsg[MAXERRLEN];

	char *my_user = (char *)user;
	datum datum_user = { my_user, (strlen( my_user )+1) };

	cached_password_timestamp cpt;
	time_t current_time;

	datum datum_value;

	char *pw = NULL;

	int MAXAGE = atoi( m->ibmdb2cachelifetime );

	GDBM_FILE gdbm;

	double time_diff;

	gdbm = gdbm_open( m->ibmdb2cachefile, 0, GDBM_WRCREAT, 00664, NULL );

	if( gdbm != NULL )
	{
		datum_value = gdbm_fetch( gdbm, datum_user );

		if( datum_value.dptr != NULL )
		{
			if( datum_value.dsize != sizeof(cpt) )
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "we found our user in the cache but with corrupted record: %s \n", my_user);
				LOG_ERROR( errmsg );
				gdbm_close( gdbm );

				return NULL;
			}
			else
			{
				memcpy((void *)&cpt, datum_value.dptr, datum_value.dsize);

				if( !(time(&(current_time))) )
				{
					errmsg[0] = '\0';
					sprintf( errmsg, "unable to determine current time (read cache)");
					LOG_ERROR( errmsg );
					gdbm_close( gdbm );

					return NULL;
				}

				time_diff = difftime( current_time, cpt.timestamp );

				if( MAXAGE < time_diff )
				{
					errmsg[0] = '\0';
					sprintf( errmsg, "cached password for user [%s] is toooo old", my_user);
					LOG_DBG( errmsg );
					gdbm_close( gdbm );

					return NULL;
				}

				pw = cpt.password;

				/* Congratulations, we have a fresh cached entry */
				errmsg[0] = '\0';
				sprintf( errmsg, "user [%s] - [%s] found in cache", my_user, pw);
				LOG_DBG( errmsg );
				gdbm_close(gdbm);

				return pw;
			}
		}
		else
		{
			/* Did not find user in the cache */
			errmsg[0] = '\0';
			sprintf( errmsg, "user [%s] not found in cache", my_user);
			LOG_DBG( errmsg );
			gdbm_close( gdbm );

			return NULL;
		}
	}
	else
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "could not open cachefile [%s] for reading", m->ibmdb2cachefile );
		LOG_ERROR( errmsg );

		return NULL;
	}
}
/* }}} */

/*
	function to store the group information in the local cache, so that subsequent
	http requests can validate the groups directly from local cache without the need
	to query the backend db2 database.
*/

/* {{{ static int write_group_cache( request_rec *r, const char *user, const char **grplist, authn_ibmdb2_config_t *m )
*/
static int write_group_cache( request_rec *r, const char *user, const char **grplist, authn_ibmdb2_config_t *m )
{
	char errmsg[MAXERRLEN];

	char ibmdb2grpcachefile[512];
	char username[MAX_UID_LENGTH+4];
	char groupname[MAX_GRP_LENGTH];

	int i = 0;

	char *my_user = (char *)user;
	datum datum_user = { my_user, (strlen( my_user )+1) };

	cached_group_timestamp cgt;

	datum datum_value;
	datum key_data;
	datum data_data;

	GDBM_FILE gdbm;

	sprintf( ibmdb2grpcachefile, "%s.grp", m->ibmdb2cachefile );

	if ( !(time(&(cgt.timestamp))) )
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "unable to determine current time (write group cache)");
		LOG_ERROR( errmsg );
		return( 1 );
	}

	while( grplist[i] )
	{
		++i;
	}

	cgt.numgrps = i;

	datum_value.dptr = (void *)&cgt;
	datum_value.dsize = sizeof(cgt);

	gdbm = gdbm_open( ibmdb2grpcachefile, 0, GDBM_WRCREAT, 00664, NULL );

	if ( gdbm != NULL )
	{
		if( gdbm_store( gdbm, datum_user, datum_value, GDBM_REPLACE ) != 0 )
		{
			errmsg[0] = '\0';
			sprintf( errmsg, "unable to store group info for user [%s] in cache", my_user);
			LOG_DBG( errmsg );

			gdbm_close( gdbm );

	        return( 1 );
		}

		i = 0;

		while( grplist[i] )
		{
			key_data.dptr = NULL;
            data_data.dptr = NULL;

			username[0] = '\0';
			sprintf( username, "%s_%d", my_user, i );

			groupname[0] = '\0';
			strcpy( groupname, grplist[i] );

			key_data.dptr = username;
			key_data.dsize = strlen(username) + 1;

			data_data.dptr = groupname;
			data_data.dsize = strlen(groupname) + 1;

			if( gdbm_store( gdbm, key_data, data_data, GDBM_REPLACE ) != 0 )
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "unable to store group [%s] for user [%s] in cache", grplist[i], my_user );
			    LOG_DBG( errmsg );

			    gdbm_close( gdbm );

			    return( 1 );
			}
			else
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "storing user [%s] and group [%s] in cache", my_user, grplist[i] );
				LOG_DBG( errmsg );
			}

			++i;
		}

		gdbm_close( gdbm );
	}
	else
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "could not open group cachefile [%s] for writing", ibmdb2grpcachefile );
		LOG_ERROR( errmsg );
	}

	return( 0 );
}
/* }}} */

/*
	function to check in the local cache to check if user is in a group, otherwise
	we need to query the backend db2 database.
*/

/* {{{ static char **read_group_cache( request_rec *r, const char *user, authn_ibmdb2_config_t *m )
*/
static char **read_group_cache( request_rec *r, const char *user, authn_ibmdb2_config_t *m )
{
	char errmsg[MAXERRLEN];

	char ibmdb2grpcachefile[512];
	char username[MAX_UID_LENGTH+4];

	int i = 0;

	int numgrps;

	char *my_user = (char *)user;
	datum datum_user = { my_user, (strlen( my_user )+1) };

	cached_group_timestamp cgt;
	time_t current_time;

	datum datum_value;
	datum key_data;
	datum return_data;

	char **list = NULL;

	int MAXAGE = atoi( m->ibmdb2cachelifetime );

	GDBM_FILE gdbm;

	double time_diff;

	sprintf( ibmdb2grpcachefile, "%s.grp", m->ibmdb2cachefile );

	gdbm = gdbm_open( ibmdb2grpcachefile, 0, GDBM_WRCREAT, 00664, NULL );

	if( gdbm != NULL )
	{
		datum_value = gdbm_fetch( gdbm, datum_user );

		if( datum_value.dptr != NULL )
		{
			if( datum_value.dsize != sizeof(cgt) )
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "we found our user in the cache but with corrupted record: %s \n", my_user);
				LOG_ERROR( errmsg );
				gdbm_close( gdbm );

				return NULL;
			}
			else
			{
				memcpy((void *)&cgt, datum_value.dptr, datum_value.dsize);

				if( !(time(&(current_time))) )
				{
					errmsg[0] = '\0';
					sprintf( errmsg, "unable to determine current time (read group cache)");
					LOG_ERROR( errmsg );
					gdbm_close( gdbm );

					return NULL;
				}

				time_diff = difftime( current_time, cgt.timestamp );

				i = 0;

				numgrps = cgt.numgrps;

				if( MAXAGE < time_diff )
				{
					errmsg[0] = '\0';
					sprintf( errmsg, "cached group information for user [%s] toooo old", my_user);
					LOG_DBG( errmsg );
					gdbm_close( gdbm );

					return NULL;
				}

				/* Build the list to return */

				list = (char **) malloc(sizeof(char *) * (numgrps+1));

				for( i = 0; i < numgrps; i++ )
				{
					key_data.dptr = NULL;
					return_data.dptr = NULL;

					username[0] = '\0';
					sprintf( username, "%s_%d", my_user, i );

					key_data.dptr = username;
					key_data.dsize = strlen(username) + 1;

					return_data = gdbm_fetch( gdbm, key_data );

					if( return_data.dptr != 0 )
					{
						list[i] = return_data.dptr;
					}
				}

				list[i] = NULL;

				/* Congratulations, we have a fresh cached entry */
				errmsg[0] = '\0';
				sprintf( errmsg, "groups for user [%s] found in cache", my_user);
				LOG_DBG( errmsg );
				gdbm_close(gdbm);

				return list;
			}
		}
		else
		{
			/* Did not find user in the group cache */
			errmsg[0] = '\0';
			sprintf( errmsg, "groups for user [%s] not found in cache", my_user);
			LOG_DBG( errmsg );
			gdbm_close( gdbm );

			return NULL;
		}
	}
	else
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "could not open group cachefile [%s] for reading", ibmdb2grpcachefile );
		LOG_ERROR( errmsg );

		return NULL;
	}
}
/* }}} */

#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */

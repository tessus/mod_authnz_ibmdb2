/*
  +----------------------------------------------------------------------+
  | mod_authnz_ibmdb2: authentication using an IBM DB2 database          |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2014 Helmut K. C. Tessarek                        |
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

#define MODULE "mod_authnz_ibmdb2"
#define RELEASE "2.2.2"

#define PCALLOC apr_pcalloc
#define SNPRINTF apr_snprintf
#define PSTRDUP apr_pstrdup

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "mod_auth.h"

#include "sqlcli1.h"

#include "apr_env.h"
#include "apr.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "apr_strings.h"

#include "mod_authnz_ibmdb2.h"              // structures, defines, globals
#include "caching.h"                        // functions for caching mechanism
#include "sha2.h"                           // sha256 include from APR

#ifndef WIN32
#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#endif

module AP_MODULE_DECLARE_DATA authnz_ibmdb2_module;

/*
	Callback to close ibmdb2 handle when necessary. Also called when a
	child httpd process is terminated.
*/

/* {{{ static apr_status_t authnz_ibmdb2_cleanup(void *notused)
*/
static apr_status_t authnz_ibmdb2_cleanup(void *notused)
{
	SQLDisconnect( hdbc );                  // disconnect the database connection
	SQLFreeHandle( SQL_HANDLE_DBC, hdbc );  // free the connection handle
	SQLFreeHandle( SQL_HANDLE_ENV, henv );  // free the environment handle

	return APR_SUCCESS;
}
/* }}} */

/*
	create sha256 hash - make use of APR apr__SHA256* functions
	output of base64 encoded SHA256 is always 44 chars + APR_SHA256PW_IDLEN
*/

/* {{{ void sha256_base64( const char *clear, int len, char *out )
*/
void sha256_base64( const char *clear, int len, char *out )
{
	int l;
	SHA256_CTX context;
	apr_byte_t digest[SHA256_DIGEST_LENGTH];

	apr__SHA256_Init( &context );
	apr__SHA256_Update( &context, clear, len );
	apr__SHA256_Final( digest, &context );

	apr_cpystrn( out, APR_SHA256PW_ID, APR_SHA256PW_IDLEN + 1 );

	l = apr_base64_encode_binary( out + APR_SHA256PW_IDLEN, digest, sizeof(digest) );
	out[l + APR_SHA256PW_IDLEN] = '\0';
}
/* }}} */

/*
	validate a cleartext password (sent) against a hash (real)
*/

/* {{{ int validate_pw( const char *sent, const char *real )
*/
int validate_pw( const char *sent, const char *real )
{
	unsigned int i = 0;
	char md5str[33];
	char hash[60];
	unsigned char digest[APR_MD5_DIGESTSIZE];
	apr_md5_ctx_t context;
	char *r, *result;
	apr_status_t status;

	if( !strncmp( real, APR_SHA256PW_ID, APR_SHA256PW_IDLEN ) )
	{
		sha256_base64( sent, strlen(sent), hash );

		if( strcmp( real, hash ) == 0 )
			return TRUE;
		else
			return FALSE;
	}

	if( (strlen(real) == 32) && (real[0] != '$') )
	{
		md5str[0] = '\0';

		apr_md5_init( &context );
		apr_md5_update( &context, sent, strlen(sent) );
		apr_md5_final( digest, &context );
		for( i = 0, r = md5str; i < 16; i++, r += 2 )
		{
			sprintf( r, "%02x", digest[i] );
		}
		*r = '\0';

		if( apr_strnatcmp( real, md5str ) == 0 )
			return TRUE;
		else
			return FALSE;
	}

	status = apr_password_validate( sent, real );

	if( status == APR_SUCCESS )
		return TRUE;
#ifndef WIN32
	else
	{
		// maybe a different encrypted password (glibc2 crypt)?
		result = crypt( sent, real );
		if( strcmp( real, result ) == 0 )
			return TRUE;
		else
			return FALSE;
	}
#endif
}
/* }}} */

//	function to check the environment/connection handle and to return the sqlca structure

/* {{{ sqlerr_t get_handle_err( SQLSMALLINT htype, SQLHANDLE handle, SQLRETURN rc )
*/
sqlerr_t get_handle_err( SQLSMALLINT htype, SQLHANDLE handle, SQLRETURN rc )
{
	SQLCHAR message[SQL_MAX_MESSAGE_LENGTH + 1];
	SQLCHAR SQLSTATE[SQL_SQLSTATE_SIZE + 1];
	SQLINTEGER sqlcode;
	SQLSMALLINT length;
	SQLCHAR *p = NULL;

	sqlerr_t sqlerr;

	if (rc != SQL_SUCCESS)
	{
		switch( rc )
		{
			case SQL_INVALID_HANDLE:
				strcpy( sqlerr.msg, "SQL_INVALID_HANDLE" );
				break;
			case SQL_SUCCESS_WITH_INFO:
				strcpy( sqlerr.msg, "SQL_SUCCESS_WITH_INFO" );
				break;
			case SQL_ERROR:
				SQLGetDiagRec(htype, handle, 1, SQLSTATE, &sqlcode, message, SQL_MAX_MESSAGE_LENGTH + 1, &length);
#ifdef WIN32
				if (message[length-2] == '\r')
				{
					p = &message[length-2];
					*p = '\0';
				}
#endif
				if (message[length-1] == '\n')   // get rid of the next line character
				{
					p = &message[length-1];
					*p = '\0';
				}
				strcpy( sqlerr.msg, message );
				strcpy( sqlerr.state, SQLSTATE );
				sqlerr.code = sqlcode;
				break;
			default:
				break;
		}
	}
	return sqlerr;
}
/* }}} */

//	function to check the statement handle and to return the sqlca structure

/* {{{ sqlerr_t get_stmt_err( SQLHANDLE stmt, SQLRETURN rc )
*/
sqlerr_t get_stmt_err( SQLHANDLE stmt, SQLRETURN rc )
{
	SQLCHAR message[SQL_MAX_MESSAGE_LENGTH + 1];
	SQLCHAR SQLSTATE[SQL_SQLSTATE_SIZE + 1];
	SQLINTEGER sqlcode;
	SQLSMALLINT length;
	SQLCHAR *p = NULL;

	sqlerr_t sqlerr;

	if (rc != SQL_SUCCESS)
	{
		SQLGetDiagRec(SQL_HANDLE_STMT, stmt, 1, SQLSTATE, &sqlcode, message, SQL_MAX_MESSAGE_LENGTH + 1, &length);
#ifdef WIN32
		if (message[length-2] == '\r')
		{
			p = &message[length-2];
			*p = '\0';
		}
#endif
		if (message[length-1] == '\n')      // get rid of the next line character
		{
			p = &message[length-1];
			*p = '\0';
		}
		strcpy( sqlerr.msg, message );
		strcpy( sqlerr.state, SQLSTATE );
		sqlerr.code = sqlcode;
	}
	return sqlerr;
}
/* }}} */

/*
	open connection to DB server if necessary.  Return TRUE if connection
	is good, FALSE if not able to connect.  If false returned, reason
	for failure has been logged to error_log file already.
*/

/* {{{ SQLRETURN ibmdb2_connect( request_rec *r, authn_ibmdb2_config_t *m )
*/
SQLRETURN ibmdb2_connect( request_rec *r, authn_ibmdb2_config_t *m )
{
	char errmsg[MAXERRLEN];
	char dsn[MAX_DSN_LENGTH];
	char *db  = NULL;
	char *uid = NULL;
	char *pwd = NULL;
	char *host = NULL;
	int port = 0;
	sqlerr_t sqlerr;
	SQLRETURN   sqlrc = SQL_SUCCESS;
	SQLINTEGER  dead_conn = SQL_CD_TRUE;    // initialize to 'conn is dead'

	// test the database connection
	sqlrc = SQLGetConnectAttr( hdbc, SQL_ATTR_CONNECTION_DEAD, &dead_conn, 0, NULL ) ;

	if( dead_conn == SQL_CD_FALSE )         // then the connection is alive
	{
		LOG_DBG( "  DB connection is alive; re-using" );
		return SQL_SUCCESS;
	}
	else                                    // connection is dead or not yet existent
	{
		LOG_DBG( "  DB connection is dead or nonexistent; create connection" );
	}

	LOG_DBG( "  allocate an environment handle" );

	// allocate an environment handle

	sqlrc = SQLAllocHandle( SQL_HANDLE_ENV, SQL_NULL_HANDLE, &henv );

	if( sqlrc != SQL_SUCCESS )
	{
		sqlerr = get_handle_err( SQL_HANDLE_ENV, henv, sqlrc );
		LOG_ERROR( "IBMDB2 error: cannot allocate an environment handle" );
		LOG_DBG( sqlerr.msg );
		return( SQL_ERROR );
	}

	// allocate a connection handle

	sqlrc = SQLAllocHandle( SQL_HANDLE_DBC, henv, &hdbc );

	if( sqlrc != SQL_SUCCESS )
	{
		sqlerr = get_handle_err( SQL_HANDLE_ENV, henv, sqlrc );
		LOG_ERROR( "IBMDB2 error: cannot allocate a connection handle" );
		LOG_DBG( sqlerr.msg );
		return( SQL_ERROR );
	}

	// Set AUTOCOMMIT ON (all we are doing are SELECTs)

	if( SQLSetConnectAttr( hdbc, SQL_ATTR_AUTOCOMMIT, ( void * ) SQL_AUTOCOMMIT_ON, SQL_NTS ) != SQL_SUCCESS )
	{
		LOG_ERROR( "IBMDB2 error: cannot set autocommit on" );
		return( SQL_ERROR );
	}

	// make the database connection

	uid = m->ibmdb2user;
	pwd = m->ibmdb2passwd;
	db  = m->ibmdb2DB;

	host = m->ibmdb2host;
	port = m->ibmdb2port;

	if( !host || (strcmp(host, "NULL") == 0) ) // if hostname not set or not string 'NULL', assume a cataloged database
	{
		sqlrc = SQLConnect( hdbc, db, SQL_NTS, uid, SQL_NTS, pwd, SQL_NTS );
		LOG_DBG( "  SQLConnect" );
	}
	else
	{
		SNPRINTF( dsn, sizeof(dsn), "Driver={IBM DB2 ODBC DRIVER};Database=%s;Hostname=%s;Port=%d; Protocol=TCPIP;Uid=%s;Pwd=%s;", db, host, port, uid, pwd );
		sqlrc = SQLDriverConnect(hdbc, (SQLHWND)NULL, (SQLCHAR*)dsn, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT );
		LOG_DBG( "  SQLDriverConnect" );
	}

	if( sqlrc != SQL_SUCCESS )
	{
		sqlerr = get_handle_err( SQL_HANDLE_DBC, hdbc, sqlrc );
		sprintf( errmsg, "IBMDB2 error: cannot connect to %s", db );
		LOG_ERROR( errmsg );
		LOG_DBG( sqlerr.msg );
		SQLDisconnect( hdbc );
		SQLFreeHandle( SQL_HANDLE_DBC, hdbc );
		return( SQL_ERROR );
	}

	// ELSE: connection was successful

	// make sure dbconn is closed at end of request if specified

	if( !m->ibmdb2KeepAlive )               // close db connection when request done
	{
		apr_pool_cleanup_register(r->pool, (void *)NULL,
		                                    authnz_ibmdb2_cleanup,
		                                    apr_pool_cleanup_null);
	}

	return SQL_SUCCESS;
}
/* }}} */

/* {{{ SQLRETURN ibmdb2_disconnect( request_rec *r, authn_ibmdb2_config_t *m )
*/
SQLRETURN ibmdb2_disconnect( request_rec *r, authn_ibmdb2_config_t *m )
{
	if( m->ibmdb2KeepAlive )                // if persisting dbconn, return without disconnecting
	{
		LOG_DBG( "  keepalive on; do not disconnect from database" );
		return( SQL_SUCCESS );
	}

	LOG_DBG( "  keepalive off; disconnect from database" );

	SQLDisconnect( hdbc );

	LOG_DBG( "  free connection handle" );

	// free the connection handle

	SQLFreeHandle( SQL_HANDLE_DBC, hdbc );

	LOG_DBG( "  free environment handle" );

	// free the environment handle

	SQLFreeHandle( SQL_HANDLE_ENV, henv );

	return( SQL_SUCCESS );
}
/* }}} */

/* {{{ static void *create_authnz_ibmdb2_dir_config( apr_pool_t *p, char *d )
*/
static void *create_authnz_ibmdb2_dir_config( apr_pool_t *p, char *d )
{
	authn_ibmdb2_config_t *m =
		(authn_ibmdb2_config_t *)PCALLOC(p, sizeof(authn_ibmdb2_config_t));

	if( !m ) return NULL;                   // failure to get memory is a bad thing

	// DEFAULT values

	m->ibmdb2NameField     = "username";
	m->ibmdb2PasswordField = "password";
	m->ibmdb2GroupField    = "groupname";
	m->ibmdb2Crypted       = 1;                         // passwords are encrypted
	m->ibmdb2KeepAlive     = 1;                         // keep persistent connection
	m->ibmdb2Authoritative = 1;                         // we are authoritative source for users
	m->ibmdb2NoPasswd      = 0;                         // we require password
	m->ibmdb2caching       = 0;                         // user caching is turned off
	m->ibmdb2grpcaching    = 0;                         // group caching is turned off
	m->ibmdb2port          = 50000;                     // default instance port number
	m->ibmdb2cachefile     = "/tmp/auth_cred_cache";    // default cachefile
	m->ibmdb2cachelifetime = "300";                     // cache expires in 300 seconds (5 minutes)

	return m;
}
/* }}} */

/* {{{ static const command_rec authnz_ibmdb2_cmds[] =
*/
static const command_rec authnz_ibmdb2_cmds[] =
{
	AP_INIT_TAKE1("AuthIBMDB2Database", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2DB),
	OR_AUTHCFG, "ibmdb2 database name"),

	AP_INIT_TAKE1("AuthIBMDB2Hostname", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2host),
	OR_AUTHCFG, "ibmdb2 database server hostname"),

	AP_INIT_TAKE1("AuthIBMDB2Portnumber", ap_set_int_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2port),
	OR_AUTHCFG, "ibmdb2 database instance port"),

	AP_INIT_TAKE1("AuthIBMDB2User", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2user),
	OR_AUTHCFG, "ibmdb2 server user name"),

	AP_INIT_TAKE1("AuthIBMDB2Password", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2passwd),
	OR_AUTHCFG, "ibmdb2 server user password"),

	AP_INIT_TAKE1("AuthIBMDB2UserTable", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2pwtable),
	OR_AUTHCFG, "ibmdb2 user table name"),

	AP_INIT_TAKE1("AuthIBMDB2GroupTable", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2grptable),
	OR_AUTHCFG, "ibmdb2 group table name"),

	AP_INIT_TAKE1("AuthIBMDB2NameField", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2NameField),
	OR_AUTHCFG, "ibmdb2 User ID field name within table"),

	AP_INIT_TAKE1("AuthIBMDB2GroupField", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2GroupField),
	OR_AUTHCFG, "ibmdb2 Group field name within table"),

	AP_INIT_TAKE1("AuthIBMDB2PasswordField", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2PasswordField),
	OR_AUTHCFG, "ibmdb2 Password field name within table"),

	AP_INIT_FLAG("AuthIBMDB2CryptedPasswords", ap_set_flag_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2Crypted),
	OR_AUTHCFG, "ibmdb2 passwords are stored encrypted if On"),

	AP_INIT_FLAG("AuthIBMDB2KeepAlive", ap_set_flag_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2KeepAlive),
	OR_AUTHCFG, "ibmdb2 connection kept open across requests if On"),

	AP_INIT_FLAG("AuthIBMDB2Authoritative", ap_set_flag_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2Authoritative),
	OR_AUTHCFG, "ibmdb2 lookup is authoritative if On"),

	AP_INIT_FLAG("AuthIBMDB2NoPasswd", ap_set_flag_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2NoPasswd),
	OR_AUTHCFG, "If On, only check if user exists; ignore password"),

	AP_INIT_TAKE1("AuthIBMDB2UserCondition", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2UserCondition),
	OR_AUTHCFG, "condition to add to user where-clause"),

	AP_INIT_TAKE1("AuthIBMDB2GroupCondition", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2GroupCondition),
	OR_AUTHCFG, "condition to add to group where-clause"),

	AP_INIT_TAKE1("AuthIBMDB2UserProc", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2UserProc),
	OR_AUTHCFG, "stored procedure for user authentication"),

	AP_INIT_TAKE1("AuthIBMDB2GroupProc", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2GroupProc),
	OR_AUTHCFG, "stored procedure for group authentication"),

	AP_INIT_FLAG("AuthIBMDB2Caching", ap_set_flag_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2caching),
	OR_AUTHCFG, "If On, user credentials are cached"),

	AP_INIT_FLAG("AuthIBMDB2GroupCaching", ap_set_flag_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2grpcaching),
	OR_AUTHCFG, "If On, group information is cached"),

	AP_INIT_TAKE1("AuthIBMDB2CacheFile", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2cachefile),
	OR_AUTHCFG, "cachefile where user credentials are stored"),

	AP_INIT_TAKE1("AuthIBMDB2CacheLifetime", ap_set_string_slot,
	(void *) APR_OFFSETOF(authn_ibmdb2_config_t, ibmdb2cachelifetime),
	OR_AUTHCFG, "cache lifetime in seconds"),

	{ NULL }
};
/* }}} */

/* {{{ static int mod_authnz_ibmdb2_init_handler( apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s )
*/
static int mod_authnz_ibmdb2_init_handler( apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s )
{
	char release[40];
	char errmsg[MAXERRLEN];
	char *env;

	release[0] = '\0';
	SNPRINTF( release, sizeof(release), "%s/%s", MODULE, RELEASE );

	ap_add_version_component( p, release );

	errmsg[0] = '\0';
	if( apr_env_get( &env, "DB2INSTANCE", p ) != APR_SUCCESS )
		sprintf( errmsg, "DB2INSTANCE=[%s]", "not set" );
	else
		sprintf( errmsg, "DB2INSTANCE=[%s]", env );
	LOG_DBGS( errmsg );

	errmsg[0] = '\0';
	if( apr_env_get( &env, "LD_LIBRARY_PATH", p ) != APR_SUCCESS )
		sprintf( errmsg, "LD_LIBRARY_PATH=[%s]", "not set" );
	else
		sprintf( errmsg, "LD_LIBRARY_PATH=[%s]", env );
	LOG_DBGS( errmsg );

	return OK;
}
/* }}} */

/*
	Fetch and return password string from database for named user.
	If we are in NoPasswd mode, returns user name instead.
	If user or password not found, returns NULL
*/

/* {{{ static char *get_ibmdb2_pw( request_rec *r, const char *user, authn_ibmdb2_config_t *m )
*/
static char *get_ibmdb2_pw( request_rec *r, const char *user, authn_ibmdb2_config_t *m )
{
	int         rowcount = 0;

	char        errmsg[MAXERRLEN];
	int         rc = 0;
	char        query[MAX_STRING_LEN];
	char        *pw = NULL;
	sqlerr_t    sqlerr;
	SQLHANDLE   hstmt;                      // statement handle
	SQLRETURN   sqlrc = SQL_SUCCESS;

	struct
	{
		SQLINTEGER ind ;
		SQLCHAR    val[MAX_PWD_LENGTH] ;
	} passwd;                               // variable to get data from the PASSWD column

	LOG_DBG( "begin get_ibmdb2_pw()" );

	// Connect to the data source

	if( ibmdb2_connect( r, m ) != SQL_SUCCESS )
	{
		LOG_DBG( "    ibmdb2_connect() cannot connect!" );

		return NULL;
	}

	/*
		If we are using a stored procedure, then some of the other parameters
		are irrelevant. So process the stored procedure first.
	*/

	if( m->ibmdb2UserProc )
	{
		// construct SQL statement

		SNPRINTF( query, sizeof(query)-1, "CALL %s( '%s', ? )",
		          m->ibmdb2UserProc, user );

		sprintf( errmsg, "    statement=[%s]", query );
		LOG_DBG( errmsg );

		LOG_DBG( "    allocate a statement handle" );

		// allocate a statement handle

		sqlrc = SQLAllocHandle( SQL_HANDLE_STMT, hdbc, &hstmt ) ;

		LOG_DBG( "    prepare the statement" );

		// prepare the statement

		sqlrc = SQLPrepare( hstmt, query, SQL_NTS ) ;

		LOG_DBG( "    bind the parameter" );

		// bind the parameter

		sqlrc = SQLBindParameter( hstmt,
		                          1,
		                          SQL_PARAM_OUTPUT,
		                          SQL_C_CHAR, SQL_CHAR,
		                          0, 0,
		                          passwd.val, MAX_PWD_LENGTH,
		                          &passwd.ind );

		LOG_DBG( "    execute the statement" );

		// execute the statement for username

		sqlrc = SQLExecute( hstmt ) ;

		if( sqlrc != SQL_SUCCESS )          // check statement
		{
			sqlerr = get_stmt_err( hstmt, sqlrc );
			errmsg[0] = '\0';

			switch( sqlerr.code )
			{
				case -440:                  // stored procedure does not exist
				   sprintf( errmsg, "stored procedure [%s] does not exist", m->ibmdb2UserProc );
				   LOG_ERROR( errmsg );
				   LOG_DBG( sqlerr.msg );
				   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
				   ibmdb2_disconnect( r, m ) ;
				   return NULL;
				   break;
				case -551:                  // no privilege to execute stored procedure
				   sprintf( errmsg, "user [%s] does not have the privilege to execute stored procedure [%s]", m->ibmdb2user, m->ibmdb2UserProc );
				   LOG_ERROR( errmsg );
				   LOG_DBG( sqlerr.msg );
				   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
				   ibmdb2_disconnect( r, m ) ;
				   return NULL;
				   break;
				case 100:                   // no data was returned (warning, no error)
				   LOG_DBG( "    stored procedure returned no data!" );
				   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
				   ibmdb2_disconnect( r, m ) ;
				   return NULL;
				   break;
				case 445:                   // data truncated
				   LOG_DBG( "    data might be truncated!" );
				   break;
				default:
				   LOG_ERROR( "IBMDB2 error: statement cannot be processed" );
				   LOG_DBG( sqlerr.msg );
				   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
				   ibmdb2_disconnect( r, m ) ;
				   return NULL;
				   break;
			}
		}

		if( m->ibmdb2NoPasswd )
		{
			if( strcmp( passwd.val, user ) != 0 )
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "    stored procedure did not return username=[%s]", user );
				LOG_DBG( errmsg );
				return NULL;
			}
		}

		if( passwd.ind > 0 )
		{
			errmsg[0] = '\0';
			if( m->ibmdb2NoPasswd )
				sprintf( errmsg, "    user from database=[%s]", passwd.val );
			else
				sprintf( errmsg, "    password from database=[%s]", passwd.val );
			LOG_DBG( errmsg );
		}

		LOG_DBG( "    free statement handle" );

		// free the statement handle

		sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;

		// disconnect from the data source

		ibmdb2_disconnect( r, m ) ;

		if( passwd.ind > 0 )
		{
			LOG_DBG( "end get_ibmdb2_pw()" );
			pw = (char *)PSTRDUP(r->pool, passwd.val);
			return pw;
		}
		else                                // if continue handler was defined in SP
		{
			LOG_DBG( "    stored procedure returned no data!" );
			LOG_DBG( "end get_ibmdb2_pw()" );
			return NULL;
		}
	}

	/*
		If we are not checking for passwords, there may not be a password field
		in the database.  We just look up the name field value in this case
		since it is guaranteed to exist.
	*/

	if( m->ibmdb2NoPasswd )
	{
		m->ibmdb2PasswordField = m->ibmdb2NameField;
	}

	// construct SQL query

	if( m->ibmdb2UserCondition )
	{
		SNPRINTF( query, sizeof(query)-1, "SELECT rtrim(%s) FROM %s WHERE %s='%s' AND %s",
		          m->ibmdb2PasswordField, m->ibmdb2pwtable, m->ibmdb2NameField,
		          user, m->ibmdb2UserCondition);
	}
	else
	{
		SNPRINTF( query, sizeof(query)-1, "SELECT rtrim(%s) FROM %s WHERE %s='%s'",
		          m->ibmdb2PasswordField, m->ibmdb2pwtable, m->ibmdb2NameField,
		          user);
	}

	sprintf( errmsg, "    query=[%s]", query );
	LOG_DBG( errmsg );

	LOG_DBG( "    allocate a statement handle" );

	// allocate a statement handle

	sqlrc = SQLAllocHandle( SQL_HANDLE_STMT, hdbc, &hstmt ) ;

	LOG_DBG( "    prepare the statement" );

	// prepare the statement

	sqlrc = SQLPrepare( hstmt, query, SQL_NTS ) ;

	/* Maybe implemented later - later binding of username

	errmsg[0] = '\0';
	sprintf( errmsg, "bind username '%s' to the statement", user );
	LOG_DBG( errmsg );

	sqlrc = SQLBindParameter(hstmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR,
								SQL_VARCHAR, MAX_UID_LENGTH, 0, user, MAX_UID_LENGTH, NULL);

	*/

	LOG_DBG( "    execute the statement" );

	// execute the statement for username

	sqlrc = SQLExecute( hstmt ) ;

	if( sqlrc != SQL_SUCCESS )              // check statement
	{
		sqlerr = get_stmt_err( hstmt, sqlrc );

		errmsg[0] = '\0';

		switch( sqlerr.code )
		{
			case -204:                      // the table does not exist
			   sprintf( errmsg, "table [%s] does not exist", m->ibmdb2pwtable );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -206:                      // the column does not exist
			   sprintf( errmsg, "column [%s] or [%s] does not exist (or both)", m->ibmdb2PasswordField, m->ibmdb2NameField );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -551:                      // no privilege to access table
			   sprintf( errmsg, "user [%s] does not have the privilege to access table [%s]", m->ibmdb2user, m->ibmdb2pwtable );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -10:                       // syntax error in user condition [string delimiter]
			case -104:                      // syntax error in user condition [unexpected token]
			   sprintf( errmsg, "syntax error in user condition [%s]", m->ibmdb2UserCondition );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case 445:                       // data truncated
			   LOG_DBG( "    data might be truncated!" );
			   break;
			default:
			   LOG_ERROR( "IBMDB2 error: statement cannot be processed" );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
		}
	}

	LOG_DBG( "    fetch each row, and display" );

	// fetch each row, and display

	sqlrc = SQLFetch( hstmt );

	if( sqlrc == SQL_NO_DATA_FOUND )
	{
		LOG_DBG( "    query returned no data!" );
	}
	else
	{
		while( sqlrc != SQL_NO_DATA_FOUND )
		{
			rowcount++;

			LOG_DBG( "    get data from query resultset" );

			sqlrc = SQLGetData( hstmt, 1, SQL_C_CHAR, passwd.val, MAX_PWD_LENGTH,
			                    &passwd.ind ) ;

			errmsg[0] = '\0';
			sprintf( errmsg, "    password from database=[%s]", passwd.val );
			LOG_DBG( errmsg );

			LOG_DBG( "    call SQLFetch() (point to next row)" );

			sqlrc = SQLFetch( hstmt );
		}
	}

	LOG_DBG( "    free statement handle" );

	// free the statement handle

	sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;

	// disconnect from the data source

	ibmdb2_disconnect( r, m ) ;

	LOG_DBG( "end get_ibmdb2_pw()" );

	if( rowcount > 1 )
	{
		LOG_ERROR( "query returns more than 1 row -> ooops (forgot pk on username?)" );
		return NULL;
	}

	if( rowcount == 0 )
		return NULL;

	pw = (char *)PSTRDUP(r->pool, passwd.val);
	return pw;

}
/* }}} */

/*
	get list of groups from database.  Returns array of pointers to strings
	the last of which is NULL.  returns NULL pointer if user is not member
	of any groups.
*/

/* {{{ static char **get_ibmdb2_groups( request_rec *r, char *user, authn_ibmdb2_config_t *m )
*/
static char **get_ibmdb2_groups( request_rec *r, char *user, authn_ibmdb2_config_t *m )
{
	char        *gname = NULL;
	char        **list = NULL;
	char        **cachelist = NULL;
	char        query[MAX_STRING_LEN];
	char 		errmsg[MAXERRLEN];
	int         rowcount = 0;
	int         rc      = 0;
	int         numgrps = 0;
	sqlerr_t	sqlerr;
	SQLHANDLE   hstmt;                      // statement handle
	SQLRETURN   sqlrc = SQL_SUCCESS;

	struct {
		SQLINTEGER ind ;
		SQLCHAR    val[MAX_PWD_LENGTH] ;
	} group;                                // variable to get data from the GROUPNAME column

	typedef struct element
	{
		char data[MAX_GRP_LENGTH];
		struct element *next;
	} linkedlist_t;

	linkedlist_t *element, *first;

	// read group cache

	if( m->ibmdb2grpcaching )
	{
		cachelist = read_group_cache( r, user, m );

		if( cachelist != NULL )
		{
			return cachelist;
		}
	}

	LOG_DBG( "begin get_ibmdb2_groups()" );

	if( ibmdb2_connect( r, m ) != SQL_SUCCESS )
	{
		LOG_DBG( "   ibmdb2_connect() cannot connect!" );

		return NULL;
	}

	// construct SQL query

	if( m->ibmdb2GroupCondition )
	{
		SNPRINTF( query, sizeof(query)-1, "SELECT rtrim(%s) FROM %s WHERE %s='%s' AND %s",
		          m->ibmdb2GroupField, m->ibmdb2grptable, m->ibmdb2NameField,
		          user, m->ibmdb2GroupCondition );
	}
	else
	{
		SNPRINTF( query, sizeof(query)-1, "SELECT rtrim(%s) FROM %s WHERE %s='%s'",
		          m->ibmdb2GroupField, m->ibmdb2grptable, m->ibmdb2NameField,
		          user );
	}

	if( m->ibmdb2GroupProc )
	{
		query[0] = '\0';
		SNPRINTF( query, sizeof(query)-1, "CALL %s( '%s' )",
		          m->ibmdb2GroupProc, user );
	}

	errmsg[0] = '\0';
	if( m->ibmdb2GroupProc )
		sprintf( errmsg, "    statement=[%s]", query );
	else
		sprintf( errmsg, "    query=[%s]", query );
	LOG_DBG( errmsg );

	LOG_DBG( "    allocate a statement handle" );

	// allocate a statement handle

	sqlrc = SQLAllocHandle( SQL_HANDLE_STMT, hdbc, &hstmt ) ;

	LOG_DBG( "    prepare the statement" );

	// prepare the statement

	sqlrc = SQLPrepare( hstmt, query, SQL_NTS ) ;

	/* Maybe implemented later - later binding of username

	errmsg[0] = '\0';
	sprintf( errmsg, "bind username '%s' to the statement", user );
	LOG_DBG( errmsg );

	sqlrc = SQLBindParameter(hstmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR,
								SQL_VARCHAR, MAX_UID_LENGTH, 0, user, MAX_UID_LENGTH, NULL);

	*/

	LOG_DBG( "    execute the statement" );

	// execute the statement for username

	sqlrc = SQLExecute( hstmt ) ;

	if( sqlrc != SQL_SUCCESS )              // check statement
	{
		sqlerr = get_stmt_err( hstmt, sqlrc );

		errmsg[0] = '\0';

		switch( sqlerr.code )
		{
			case -204:                      // the table does not exist
			   sprintf( errmsg, "table [%s] does not exist", m->ibmdb2grptable );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -206:                      // the column does not exist
			   sprintf( errmsg, "column [%s] or [%s] does not exist (or both)", m->ibmdb2GroupField, m->ibmdb2NameField );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -551:                      // no privilege to access table or to execute stored procedure
			   if( m->ibmdb2GroupProc )
			   {
			       sprintf( errmsg, "user [%s] does not have the privilege to execute stored procedure [%s]", m->ibmdb2user, m->ibmdb2GroupProc );
			   }
			   else
			   {
			       sprintf( errmsg, "user [%s] does not have the privilege to access table [%s]", m->ibmdb2user, m->ibmdb2grptable );
			   }
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -10:                       // syntax error in group condition [string delimiter]
			case -104:                      // syntax error in group condition [unexpected token]
			   sprintf( errmsg, "syntax error in group condition [%s]", m->ibmdb2GroupCondition );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -440:                      // stored procedure does not exist
			   sprintf( errmsg, "stored procedure [%s] does not exist", m->ibmdb2UserProc );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case 445:                       // data truncated
			   LOG_DBG( "    data might be truncated!" );
			   break;
			default:
			   LOG_ERROR( "IBMDB2 error: statement cannot be processed" );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
		}
	}

	LOG_DBG( "    fetch each row, and display" );

	// fetch each row, and display

	sqlrc = SQLFetch( hstmt );

	element = (linkedlist_t *)malloc(sizeof(linkedlist_t));
	first = element;


	if( sqlrc == SQL_NO_DATA_FOUND )
	{
		LOG_DBG( "    query returned no data!" );
		return NULL;
	}
	else
	{
		// Building linked list

		element->next = NULL;

		while( sqlrc != SQL_NO_DATA_FOUND )
		{
			rowcount++;                     // record counter

			LOG_DBG( "    get data from query resultset" );

			sqlrc = SQLGetData( hstmt, 1, SQL_C_CHAR, group.val, MAX_GRP_LENGTH,
			                    &group.ind ) ;

			if( element->next == NULL )
			{
				strcpy( element->data, group.val );
				element->next = malloc(sizeof(linkedlist_t));
				element = element->next;
				element->next = NULL;
			}

			errmsg[0] = '\0';
			sprintf( errmsg, "    group #%i from database=[%s]", rowcount, group.val );
			LOG_DBG( errmsg );

			LOG_DBG( "    call SQLFetch() (point to next row)" );

			sqlrc = SQLFetch( hstmt );
		}
	}

	LOG_DBG( "    free statement handle" );

	// free the statement handle

	sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;

	// disconnect from the data source

	ibmdb2_disconnect( r, m ) ;

	LOG_DBG( "end get_ibmdb2_groups()" );

	// Building list to be returned

	numgrps = 0;

	list = (char **) PCALLOC(r->pool, sizeof(char *) * (rowcount+1));

	element = first;

	while( element->next != NULL )
	{
		if( element->data )
			list[numgrps] = (char *) PSTRDUP(r->pool, element->data);
		else
			list[numgrps] = "";             // if no data, make it empty, not NULL

		numgrps++;
		element=element->next;
	}

	list[numgrps] = NULL;                   // last element in array is NULL

	// Free memory of linked list

	element = first;

	while( first->next != NULL )
	{
		first = element->next;
		free(element);
		element=first;
	}

	free(first);

	// End of freeing memory of linked list

	// write group cache

	if( m->ibmdb2grpcaching )
	{
		write_group_cache( r, user, (const char**)list, m );
	}

	// Returning list

	return list;
}
/* }}} */

//	callback from Apache to do the authentication of the user to his password

/* {{{ static int authn_ibmdb2_check_authentication( request_rec *r, const char *user, const char *sent_pw )
*/
static authn_status authn_ibmdb2_check_authentication( request_rec *r, const char *user, const char *sent_pw )
{
	authn_ibmdb2_config_t *sec = (authn_ibmdb2_config_t *)ap_get_module_config (r->per_dir_config, &authnz_ibmdb2_module);
	conn_rec   *c = r->connection;
	const char *real_pw;
	int passwords_match = 0;
	char errmsg[MAXERRLEN];

	errmsg[0] = '\0';

	sprintf( errmsg, "begin authenticate for user=[%s], uri=[%s]", user, r->uri );
	LOG_DBG( errmsg );

	// not configured for ibmdb2 authorization

	if( !sec->ibmdb2pwtable && !sec->ibmdb2UserProc )
	{
		LOG_DBG( "ibmdb2pwtable not set, return AUTH_DENIED" );
		LOG_DBG( "end authenticate" );

		return AUTH_DENIED;
	}

	// Caching

	if( sec->ibmdb2caching )
	{
		if( real_pw = read_cache( r, user, sec ) )
		{
			if( sec->ibmdb2NoPasswd )
			{
				return AUTH_GRANTED;
			}

			if( sec->ibmdb2Crypted )
			{
				passwords_match = validate_pw( sent_pw, real_pw );
			}
			else
			{
				if( strcmp( sent_pw, real_pw ) == 0 )
				   passwords_match = 1;
			}
		}

		if( passwords_match )
		{
			return AUTH_GRANTED;
		}
	}

	// Caching End

	if( !(real_pw = get_ibmdb2_pw(r, user, sec)) )
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "cannot find user [%s] in db; sent pw=[%s]", user, sent_pw );
		LOG_DBG( errmsg );

		// user not found in database

		if( !sec->ibmdb2Authoritative )
		{
			LOG_DBG( "ibmdb2Authoritative is Off, return AUTH_DENIED" );
			LOG_DBG( "end authenticate" );

			return AUTH_DENIED;             // let other schemes find user
		}

		errmsg[0] = '\0';
		sprintf( errmsg, "user [%s] not found; uri=[%s]", user, r->uri );
		LOG_DBG( errmsg );

		ap_note_basic_auth_failure(r);

		return AUTH_USER_NOT_FOUND;
	}

	// if we don't require password, just return ok since they exist
	if( sec->ibmdb2NoPasswd )
	{
		return AUTH_GRANTED;
	}

	// validate the password

	if( sec->ibmdb2Crypted )
	{
		passwords_match = validate_pw( sent_pw, real_pw );
	}
	else
	{
		if( strcmp( sent_pw, real_pw ) == 0 )
			passwords_match = 1;
	}

	if( passwords_match )
	{
		if( sec->ibmdb2caching )            // Caching
		{
			write_cache( r, user, real_pw, sec );
		}

		return AUTH_GRANTED;
	}
	else
	{
		// Error message is generated by Apache

		ap_note_basic_auth_failure(r);

		return AUTH_DENIED;
	}
}
/* }}} */

//	check if user is member of at least one of the necessary group(s)

#if defined(APACHE24)
/* {{{ static authz_status authz_ibmdb2_check_authorization( request_rec *r, const char *require_args, const void *parsed_require_args )
*/
static authz_status authz_ibmdb2_check_authorization( request_rec *r, const char *require_args, const void *parsed_require_args )
{
	authn_ibmdb2_config_t *sec = (authn_ibmdb2_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ibmdb2_module);

	char errmsg[MAXERRLEN];

	char *user = r->user;

	const char *t;
	char *want;

	register int x;
	char **groups = NULL;

	if (!user)
	{
		return AUTHZ_DENIED_NO_USER;
	}

	// if the group table is not specified, use the same as for password
	if( !sec->ibmdb2grptable && !sec->ibmdb2UserProc )
	{
		sec->ibmdb2grptable = sec->ibmdb2pwtable;
	}

	if( !(groups = get_ibmdb2_groups(r, user, sec)) )
	{
		errmsg[0] = '\0';
		if( sec->ibmdb2GroupProc )
		{
			sprintf( errmsg, "user [%s] not returned from SP [%s]; uri=[%s]", user, sec->ibmdb2GroupProc, r->uri );
		}
		else
		{
			sprintf( errmsg, "user [%s] not in group table [%s]; uri=[%s]", user, sec->ibmdb2grptable, r->uri );
		}
		LOG_DBG( errmsg );

		return AUTHZ_DENIED;
	}

	t = require_args;
	while ((want = ap_getword_conf(r->pool, &t)) && want[0])
	{
		int i = 0;

		// compare against each group to which this user belongs
		while( groups[i] )
		{
			// last element is NULL
			if( !strcmp(groups[i],want) )
				return AUTHZ_GRANTED;       // we found the user!

			++i;
		}
	}

	errmsg[0] = '\0';
	sprintf( errmsg, "user [%s] not in right group; uri=[%s]", user, r->uri );
	LOG_ERROR( errmsg );

	return AUTHZ_DENIED;
}
/* }}} */
#else
/* {{{ static int authz_ibmdb2_check_authorization( request_rec *r )
*/
static int authz_ibmdb2_check_authorization( request_rec *r )
{
	authn_ibmdb2_config_t *sec = (authn_ibmdb2_config_t *)ap_get_module_config(r->per_dir_config, &authnz_ibmdb2_module);

	char errmsg[MAXERRLEN];

	char *user = r->user;

	int method = r->method_number;

	const apr_array_header_t *reqs_arr = ap_requires(r);

	require_line *reqs = reqs_arr ? (require_line *)reqs_arr->elts : NULL;

	register int x;
	char **groups = NULL;

	if( !sec->ibmdb2GroupField )
	{
		return DECLINED;                    // not doing groups here
	}
	if( !reqs_arr )
	{
		return DECLINED;                    // no "require" line in access config
	}

	// if the group table is not specified, use the same as for password

	if( !sec->ibmdb2grptable && !sec->ibmdb2UserProc )
	{
		sec->ibmdb2grptable = sec->ibmdb2pwtable;
	}

	for( x = 0; x < reqs_arr->nelts; x++ )
	{
		const char *t, *want;

		if( !(reqs[x].method_mask & (1 << method)) )
			continue;

		t = reqs[x].requirement;
		want = ap_getword(r->pool, &t, ' ');

		if( !strcmp(want,"group") )
		{
			// check for list of groups from database only first time thru

			if( !groups && !(groups = get_ibmdb2_groups(r, user, sec)) )
			{
				errmsg[0] = '\0';
				if( sec->ibmdb2GroupProc )
				{
					sprintf( errmsg, "user [%s] not returned from SP [%s]; uri=[%s]", user, sec->ibmdb2GroupProc, r->uri );
				}
				else
				{
					sprintf( errmsg, "user [%s] not in group table [%s]; uri=[%s]", user, sec->ibmdb2grptable, r->uri );
				}
				LOG_DBG( errmsg );

				ap_note_basic_auth_failure(r);

				return HTTP_UNAUTHORIZED;
			}

			// loop through list of groups specified in the directives

			while( t[0] )
			{
				int i = 0;
				want = ap_getword(r->pool, &t, ' ');

				// compare against each group to which this user belongs

				while( groups[i] )
				{
					// last element is NULL
					if( !strcmp(groups[i],want) )
						return OK;          // we found the user!

					++i;
				}
			}

			errmsg[0] = '\0';
			sprintf( errmsg, "user [%s] not in right group; uri=[%s]", user, r->uri );
			LOG_ERROR( errmsg );

			ap_note_basic_auth_failure(r);

			return HTTP_UNAUTHORIZED;
		}
	}

	return DECLINED;
}
/* }}} */
#endif

/* {{{ static const authn_provider authn_ibmdb2_provider =
*/
static const authn_provider authn_ibmdb2_provider =
{
	&authn_ibmdb2_check_authentication,
};
/* }}} */

#if defined(APACHE24)
/* {{{ static const authz_provider authz_ibmdb2_provider =
*/
static const authz_provider authz_ibmdb2_provider =
{
	&authz_ibmdb2_check_authorization,
	NULL,
};
/* }}} */
#endif

/* {{{ static void register_hooks(apr_pool_t *p)
*/
static void register_hooks(apr_pool_t *p)
{
#if defined(APACHE24)
	ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "ibmdb2",
	                          AUTHN_PROVIDER_VERSION,
	                          &authn_ibmdb2_provider,
	                          AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "group",
	                          AUTHZ_PROVIDER_VERSION,
	                          &authz_ibmdb2_provider,
	                          AP_AUTH_INTERNAL_PER_CONF);
#else
	ap_register_provider(p, AUTHN_PROVIDER_GROUP, "ibmdb2", "0", &authn_ibmdb2_provider);
	ap_hook_auth_checker(authz_ibmdb2_check_authorization, NULL, NULL, APR_HOOK_MIDDLE);
#endif
	ap_hook_post_config(mod_authnz_ibmdb2_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
}
/* }}} */

#if defined(APACHE24)
/* {{{ AP_DECLARE_MODULE(authnz_ibmdb2) =
*/
AP_DECLARE_MODULE(authnz_ibmdb2) =
#else
/* {{{ module AP_MODULE_DECLARE_DATA authnz_ibmdb2_module =
*/
module AP_MODULE_DECLARE_DATA authnz_ibmdb2_module =
#endif
{
	STANDARD20_MODULE_STUFF,
	create_authnz_ibmdb2_dir_config,        // dir config creater
	NULL,                                   // dir merger --- default is to override
	NULL,                                   // server config
	NULL,                                   // merge server config
	authnz_ibmdb2_cmds,                     // command apr_table_t
	register_hooks                          // register hooks
};
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */

"""Builds the CFFI definitions for accessing the Net-SNMP library"""

from cffi import FFI

USM_AUTH_KU_LEN = 64
USM_PRIV_KU_LEN = 64

ffi = FFI()
_custom_typedefs = """
/* Struct to hold custom session callback data (callback_magic value) */
typedef struct _callback_data {
    void          *reserved;
    unsigned long  session_id;
} _callback_data;
"""
_CDEF = f"""
/* Typedefs and structs we will be needing access to */
typedef unsigned long u_long;
typedef unsigned short u_short;
typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned long oid;
typedef struct timeval {{
    long tv_sec;
    long tv_usec;
}};


typedef struct {{ ...; }} fd_set;

/* Forward declarations needed for session callbacks */
typedef struct snmp_pdu netsnmp_pdu;
typedef struct snmp_session netsnmp_session;
typedef int     (*netsnmp_callback) (int, netsnmp_session *, int,
                                          netsnmp_pdu *, void *);


typedef struct netsnmp_container_s;

struct counter64 {{
    u_long          high;
    u_long          low;
}};
typedef union {{
   long             *integer;
   u_char           *string;
   oid              *objid;
   u_char           *bitstring;
   struct counter64 *counter64;
   float            *floatVal;
   double           *doubleVal;
   ...;
}} netsnmp_vardata;

typedef struct variable_list {{
   struct variable_list *next_variable;
   oid                  *name;
   size_t                name_length;
   u_char                type;
   netsnmp_vardata       val;
   size_t                val_len;
   ...;
}} netsnmp_variable_list;

typedef struct snmp_pdu {{
    long            reqid;
    /** Error status (non_repeaters in GetBulk) */
    long            errstat;
    /** Error index (max_repetitions in GetBulk) */
    long            errindex;
    netsnmp_variable_list *variables;
    ...;
}} netsnmp_pdu;

struct snmp_session {{
    long                 version;
    int                  retries;
    long                 timeout;
    u_long               flags;
    struct snmp_session *subsession;
    struct snmp_session *next;

    char           *peername;
    u_short         remote_port;  // DEPRECATED, use peername
    char           *localname;
    u_short         local_port;

    u_char           *(*authenticator) (u_char *, size_t *, u_char *, size_t);
    netsnmp_callback  callback;
    void             *callback_magic;
    int               s_errno;
    int               s_snmp_errno;
    long              sessid;

    u_char         *community;
    size_t          community_len;
    size_t          rcvMsgMaxSize;
    size_t          sndMsgMaxSize;

    u_char          isAuthoritative;
    u_char         *contextEngineID;
    size_t          contextEngineIDLen;
    u_int           engineBoots;
    u_int           engineTime;
    char           *contextName;
    size_t          contextNameLen;
    u_char         *securityEngineID;
    size_t          securityEngineIDLen;
    char           *securityName;
    size_t          securityNameLen;

    oid            *securityAuthProto;
    size_t          securityAuthProtoLen;
    u_char          securityAuthKey[{USM_AUTH_KU_LEN}];
    size_t          securityAuthKeyLen;
    u_char          *securityAuthLocalKey;
    size_t          securityAuthLocalKeyLen;

    oid            *securityPrivProto;
    size_t          securityPrivProtoLen;
    u_char          securityPrivKey[{USM_PRIV_KU_LEN}];
    size_t          securityPrivKeyLen;
    u_char          *securityPrivLocalKey;
    size_t          securityPrivLocalKeyLen;

    int             securityModel;
    int             securityLevel;
    char           *paramName;

    void           *securityInfo;

    struct netsnmp_container_s *transport_configuration;

    void           *myvoid;
    ...;
}};

typedef struct netsnmp_large_fd_set_s {{ ...; }} netsnmp_large_fd_set;

/* Definitions needed for logging */
struct snmp_log_message {{
    int          priority;
    const char  *msg;
}};
typedef int (SNMPCallback) (int majorID, int minorID,
                            void *serverarg, void *clientarg);
typedef struct {{ ...; }} netsnmp_log_handler;


/* Function prototypes we will be needing access to */
const char *netsnmp_get_version(void);
netsnmp_pdu *snmp_pdu_create(int type);
void snmp_free_pdu( netsnmp_pdu *pdu);
netsnmp_variable_list *snmp_add_null_var(netsnmp_pdu *pdu, const oid * name, size_t name_length);
int                    snmp_add_var(netsnmp_pdu *, const oid *, size_t, char, const char *);

void   netsnmp_large_fd_set_init(netsnmp_large_fd_set *fdset, int setsize);
void   netsnmp_large_fd_set_cleanup(netsnmp_large_fd_set *fdset);
int    netsnmp_large_fd_is_set(int fd, netsnmp_large_fd_set *fdset);
void   netsnmp_large_fd_setfd( int fd, netsnmp_large_fd_set *fdset);


int                  snmp_register_callback(int major, int minor, SNMPCallback * new_callback, void *arg);
netsnmp_log_handler *netsnmp_register_loghandler( int type, int pri );
void                 snmp_set_do_debugging(int);
extern "Python" int  python_log_callback(int, int, void*, void*);

/* Error handling functions */
void            snmp_sess_perror (char * msg, struct snmp_session *);
void            snmp_error (netsnmp_session *session,
                            int *pcliberr, int *psnmperr, char **pperrstring);

/* Traditional session API from session_api.h */
void            snmp_sess_init(netsnmp_session *);

netsnmp_session *snmp_open(netsnmp_session *);
int             snmp_close(netsnmp_session *);
int             snmp_send(netsnmp_session *, netsnmp_pdu *);
int             snmp_async_send(netsnmp_session *, netsnmp_pdu *,
                                netsnmp_callback, void *);

void            snmp_read(fd_set *);
void            snmp_read2(netsnmp_large_fd_set *);
int             snmp_synch_response(netsnmp_session *, netsnmp_pdu *,
                                    netsnmp_pdu **);
void            snmp_timeout(void);

int             snmp_select_info(int *, fd_set *, struct timeval *,
                                 int *);
int             snmp_select_info2(int *, netsnmp_large_fd_set *,
                                  struct timeval *, int *);

/* Statically declare our own session callback function */
extern "Python"  int  _netsnmp_session_callback(int, netsnmp_session*, int,
                                                netsnmp_pdu*, void*);

/* MIB parsing functions */
void         *snmp_parse_oid(const char *input,
                             oid *objid, size_t *objidlen);
void          netsnmp_init_mib(void);
void         *read_all_mibs(void);
int           snprint_variable(char *buf, size_t buf_len,
                               const oid * objid, size_t objidlen,
                               const netsnmp_variable_list * variable);
int           snprint_objid(char *buf, size_t buf_len,
                            const oid * objid, size_t objidlen);

/* Some data allocated by Net-SNMP must be freed by the caller */
void free(void *ptr);

{_custom_typedefs}
"""

ffi.cdef(_CDEF)

ffi.set_source(
    "netsnmpy._netsnmp",
    f"""
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

{_custom_typedefs}
""",
    libraries=["netsnmp"],
    library_dirs=["/usr/lib"],
    include_dirs=["/usr/include"],
    # net-snmp header files are full of warnings we can't do anything about
    extra_compile_args=[
        "-Wno-implicit-function-declaration",
        "-Wno-deprecated-declarations",
    ],
)

if __name__ == "__main__":
    ffi.compile()

"""Defines Python versions of constants defined in Net-SNMP 5.9's C headers"""

USM_LENGTH_OID_TRANSFORM = 10
NULL = None
MAX_CALLBACK_IDS = 2
MAX_CALLBACK_SUBIDS = 16
SNMP_CALLBACK_LIBRARY = 0
SNMP_CALLBACK_APPLICATION = 1
SNMP_CALLBACK_POST_READ_CONFIG = 0
SNMP_CALLBACK_STORE_DATA = 1
SNMP_CALLBACK_SHUTDOWN = 2
SNMP_CALLBACK_POST_PREMIB_READ_CONFIG = 3
SNMP_CALLBACK_LOGGING = 4
SNMP_CALLBACK_SESSION_INIT = 5
SNMP_CALLBACK_PRE_READ_CONFIG = 7
SNMP_CALLBACK_PRE_PREMIB_READ_CONFIG = 8
NETSNMP_CALLBACK_HIGHEST_PRIORITY = -1024
NETSNMP_CALLBACK_DEFAULT_PRIORITY = 0
NETSNMP_CALLBACK_LOWEST_PRIORITY = 1024
PARSE_PACKET = 0
DUMP_PACKET = 1
MIN_OID_LEN = 2
MAX_OID_LEN = 128
MAX_NAME_LEN = MAX_OID_LEN
ASN_BOOLEAN = 0x01
ASN_INTEGER = 0x02
ASN_BIT_STR = 0x03
ASN_OCTET_STR = 0x04
ASN_NULL = 0x05
ASN_OBJECT_ID = 0x06
ASN_SEQUENCE = 0x10
ASN_SET = 0x11
ASN_UNIVERSAL = 0x00
ASN_APPLICATION = 0x40
ASN_CONTEXT = 0x80
ASN_PRIVATE = 0xC0
ASN_PRIMITIVE = 0x00
ASN_CONSTRUCTOR = 0x20
ASN_LONG_LEN = 0x80
ASN_EXTENSION_ID = 0x1F
ASN_BIT8 = 0x80
ASN_OPAQUE_TAG1 = ASN_CONTEXT | ASN_EXTENSION_ID
ASN_OPAQUE_TAG2 = 0x30
ASN_OPAQUE_TAG2U = 0x2F
ASN_APP_OPAQUE = ASN_APPLICATION | 4
ASN_APP_COUNTER64 = ASN_APPLICATION | 6
ASN_APP_FLOAT = ASN_APPLICATION | 8
ASN_APP_DOUBLE = ASN_APPLICATION | 9
ASN_APP_I64 = ASN_APPLICATION | 10
ASN_APP_U64 = ASN_APPLICATION | 11
ASN_APP_UNION = ASN_PRIVATE | 1
ASN_OPAQUE_COUNTER64 = ASN_OPAQUE_TAG2 + ASN_APP_COUNTER64
ASN_OPAQUE_COUNTER64_MX_BER_LEN = 12
ASN_OPAQUE_FLOAT = ASN_OPAQUE_TAG2 + ASN_APP_FLOAT
ASN_OPAQUE_FLOAT_BER_LEN = 7
ASN_OPAQUE_DOUBLE = ASN_OPAQUE_TAG2 + ASN_APP_DOUBLE
ASN_OPAQUE_DOUBLE_BER_LEN = 11
ASN_OPAQUE_I64 = ASN_OPAQUE_TAG2 + ASN_APP_I64
ASN_OPAQUE_I64_MX_BER_LEN = 11
ASN_OPAQUE_U64 = ASN_OPAQUE_TAG2 + ASN_APP_U64
ASN_OPAQUE_U64_MX_BER_LEN = 12
ASN_PRIV_INCL_RANGE = ASN_PRIVATE | 2
ASN_PRIV_EXCL_RANGE = ASN_PRIVATE | 3
ASN_PRIV_DELEGATED = ASN_PRIVATE | 5
ASN_PRIV_IMPLIED_OCTET_STR = ASN_PRIVATE | ASN_OCTET_STR
ASN_PRIV_IMPLIED_OBJECT_ID = ASN_PRIVATE | ASN_OBJECT_ID
ASN_PRIV_RETRY = ASN_PRIVATE | 7
SNMP_PORT = 161
SNMP_TRAP_PORT = 162
SNMP_MAX_LEN = 1500
SNMP_MIN_MAX_LEN = 484
SNMP_VERSION_1 = 0
SNMP_VERSION_2c = 1
SNMP_VERSION_2u = 2
SNMP_VERSION_3 = 3
SNMP_VERSION_sec = 128
SNMP_VERSION_2p = 129
SNMP_VERSION_2star = 130
SNMP_MSG_GET = ASN_CONTEXT | ASN_CONSTRUCTOR | 0x0
SNMP_MSG_GETNEXT = ASN_CONTEXT | ASN_CONSTRUCTOR | 0x1
SNMP_MSG_RESPONSE = ASN_CONTEXT | ASN_CONSTRUCTOR | 0x2
SNMP_MSG_SET = ASN_CONTEXT | ASN_CONSTRUCTOR | 0x3
SNMP_MSG_TRAP = ASN_CONTEXT | ASN_CONSTRUCTOR | 0x4
SNMP_MSG_GETBULK = ASN_CONTEXT | ASN_CONSTRUCTOR | 0x5
SNMP_MSG_INFORM = ASN_CONTEXT | ASN_CONSTRUCTOR | 0x6
SNMP_MSG_TRAP2 = ASN_CONTEXT | ASN_CONSTRUCTOR | 0x7
SNMP_MSG_REPORT = ASN_CONTEXT | ASN_CONSTRUCTOR | 0x8
SNMP_MSG_INTERNAL_SET_BEGIN = -1
SNMP_MSG_INTERNAL_SET_RESERVE1 = 0
SNMP_MSG_INTERNAL_SET_RESERVE2 = 1
SNMP_MSG_INTERNAL_SET_ACTION = 2
SNMP_MSG_INTERNAL_SET_COMMIT = 3
SNMP_MSG_INTERNAL_SET_FREE = 4
SNMP_MSG_INTERNAL_SET_UNDO = 5
SNMP_MSG_INTERNAL_SET_MAX = 6
SNMP_MSG_INTERNAL_CHECK_VALUE = 17
SNMP_MSG_INTERNAL_ROW_CREATE = 18
SNMP_MSG_INTERNAL_UNDO_SETUP = 19
SNMP_MSG_INTERNAL_SET_VALUE = 20
SNMP_MSG_INTERNAL_CHECK_CONSISTENCY = 21
SNMP_MSG_INTERNAL_UNDO_SET = 22
SNMP_MSG_INTERNAL_COMMIT = 23
SNMP_MSG_INTERNAL_UNDO_COMMIT = 24
SNMP_MSG_INTERNAL_IRREVERSIBLE_COMMIT = 25
SNMP_MSG_INTERNAL_UNDO_CLEANUP = 26
SNMP_MSG_INTERNAL_PRE_REQUEST = 128
SNMP_MSG_INTERNAL_OBJECT_LOOKUP = 129
SNMP_MSG_INTERNAL_POST_REQUEST = 130
SNMP_MSG_INTERNAL_GET_STASH = 131
SNMP_NOSUCHOBJECT = ASN_CONTEXT | ASN_PRIMITIVE | 0x0
SNMP_NOSUCHINSTANCE = ASN_CONTEXT | ASN_PRIMITIVE | 0x1
SNMP_ENDOFMIBVIEW = ASN_CONTEXT | ASN_PRIMITIVE | 0x2
SNMP_ERR_NOERROR = 0
SNMP_ERR_TOOBIG = 1
SNMP_ERR_NOSUCHNAME = 2
SNMP_ERR_BADVALUE = 3
SNMP_ERR_READONLY = 4
SNMP_ERR_GENERR = 5
SNMP_ERR_NOACCESS = 6
SNMP_ERR_WRONGTYPE = 7
SNMP_ERR_WRONGLENGTH = 8
SNMP_ERR_WRONGENCODING = 9
SNMP_ERR_WRONGVALUE = 10
SNMP_ERR_NOCREATION = 11
SNMP_ERR_INCONSISTENTVALUE = 12
SNMP_ERR_RESOURCEUNAVAILABLE = 13
SNMP_ERR_COMMITFAILED = 14
SNMP_ERR_UNDOFAILED = 15
SNMP_ERR_AUTHORIZATIONERROR = 16
SNMP_ERR_NOTWRITABLE = 17
SNMP_ERR_INCONSISTENTNAME = 18
MAX_SNMP_ERR = 18
SNMP_TRAP_COLDSTART = 0
SNMP_TRAP_WARMSTART = 1
SNMP_TRAP_LINKDOWN = 2
SNMP_TRAP_LINKUP = 3
SNMP_TRAP_AUTHFAIL = 4
SNMP_TRAP_EGPNEIGHBORLOSS = 5
SNMP_TRAP_ENTERPRISESPECIFIC = 6
SNMP_ROW_NONEXISTENT = 0
SNMP_ROW_ACTIVE = 1
SNMP_ROW_NOTINSERVICE = 2
SNMP_ROW_NOTREADY = 3
SNMP_ROW_CREATEANDGO = 4
SNMP_ROW_CREATEANDWAIT = 5
SNMP_ROW_DESTROY = 6
SNMP_STORAGE_NONE = 0
SNMP_STORAGE_OTHER = 1
SNMP_STORAGE_VOLATILE = 2
SNMP_STORAGE_NONVOLATILE = 3
SNMP_STORAGE_PERMANENT = 4
SNMP_STORAGE_READONLY = 5
SNMP_MP_MODEL_SNMPv1 = 0
SNMP_MP_MODEL_SNMPv2c = 1
SNMP_MP_MODEL_SNMPv2u = 2
SNMP_MP_MODEL_SNMPv3 = 3
SNMP_MP_MODEL_SNMPv2p = 256
SNMP_SEC_MODEL_ANY = 0
SNMP_SEC_MODEL_SNMPv1 = 1
SNMP_SEC_MODEL_SNMPv2c = 2
SNMP_SEC_MODEL_USM = 3
SNMP_SEC_MODEL_TSM = 4
SNMP_SEC_MODEL_SNMPv2p = 256
SNMP_SEC_LEVEL_NOAUTH = 1
SNMP_SEC_LEVEL_AUTHNOPRIV = 2
SNMP_SEC_LEVEL_AUTHPRIV = 3
SNMP_MSG_FLAG_AUTH_BIT = 0x01
SNMP_MSG_FLAG_PRIV_BIT = 0x02
SNMP_MSG_FLAG_RPRT_BIT = 0x04
UCD_MSG_FLAG_RESPONSE_PDU = 0x100
UCD_MSG_FLAG_EXPECT_RESPONSE = 0x200
UCD_MSG_FLAG_FORCE_PDU_COPY = 0x400
UCD_MSG_FLAG_ALWAYS_IN_VIEW = 0x800
UCD_MSG_FLAG_PDU_TIMEOUT = 0x1000
UCD_MSG_FLAG_ONE_PASS_ONLY = 0x2000
UCD_MSG_FLAG_TUNNELED = 0x4000
SNMP_VIEW_INCLUDED = 1
SNMP_VIEW_EXCLUDED = 2
SNMP_OID_INTERNET = 1, 3, 6, 1
SNMP_OID_ENTERPRISES = SNMP_OID_INTERNET, 4, 1
SNMP_OID_MIB2 = SNMP_OID_INTERNET, 2, 1
SNMP_OID_SNMPV2 = SNMP_OID_INTERNET, 6
SNMP_OID_SNMPMODULES = SNMP_OID_SNMPV2, 3
SNMPADMINLENGTH = 255
SNMP_DEFAULT_COMMUNITY_LEN = 0
SNMP_DEFAULT_RETRIES = -1
SNMP_DEFAULT_TIMEOUT = -1
SNMP_DEFAULT_REMPORT = 0
SNMP_DEFAULT_REQID = -1
SNMP_DEFAULT_MSGID = -1
SNMP_DEFAULT_ERRSTAT = -1
SNMP_DEFAULT_ERRINDEX = -1
SNMP_DEFAULT_ADDRESS = 0
SNMP_DEFAULT_PEERNAME = NULL
SNMP_DEFAULT_ENTERPRISE_LENGTH = 0
SNMP_DEFAULT_TIME = 0
SNMP_DEFAULT_VERSION = -1
SNMP_DEFAULT_SECMODEL = -1
SNMP_DEFAULT_CONTEXT = ""
SNMP_DEFAULT_AUTH_PROTOLEN = USM_LENGTH_OID_TRANSFORM
SNMP_DEFAULT_PRIV_PROTOLEN = USM_LENGTH_OID_TRANSFORM
SNMP_MAX_MSG_SIZE = 1472
SNMP_MAX_MSG_V3_HDRS = 4 + 3 + 4 + 7 + 7 + 3 + 7 + 16
SNMP_MAX_ENG_SIZE = 32
SNMP_MAX_SEC_NAME_SIZE = 256
SNMP_MAX_CONTEXT_SIZE = 256
SNMP_SEC_PARAM_BUF_SIZE = 256
SNMPV3_IGNORE_UNAUTH_REPORTS = 0
SNMP_SESS_NONAUTHORITATIVE = 0
SNMP_SESS_AUTHORITATIVE = 1
SNMP_SESS_UNKNOWNAUTH = 2
REPORT_STATS_LEN = 9
REPORT_STATS_LEN2 = 8
REPORT_snmpUnknownSecurityModels_NUM = 1
REPORT_snmpInvalidMsgs_NUM = 2
REPORT_snmpUnknownPDUHandlers_NUM = 3
REPORT_usmStatsUnsupportedSecLevels_NUM = 1
REPORT_usmStatsNotInTimeWindows_NUM = 2
REPORT_usmStatsUnknownUserNames_NUM = 3
REPORT_usmStatsUnknownEngineIDs_NUM = 4
REPORT_usmStatsWrongDigests_NUM = 5
REPORT_usmStatsDecryptionErrors_NUM = 6
REPORT_snmpUnavailableContexts_NUM = 4
REPORT_snmpUnknownContexts_NUM = 5
SNMP_DETAIL_SIZE = 512
SNMP_FLAGS_UDP_BROADCAST = 0x800
SNMP_FLAGS_RESP_CALLBACK = 0x400
SNMP_FLAGS_USER_CREATED = 0x200
SNMP_FLAGS_DONT_PROBE = 0x100
SNMP_FLAGS_STREAM_SOCKET = 0x80
SNMP_FLAGS_LISTENING = 0x40
SNMP_FLAGS_SUBSESSION = 0x20
SNMP_FLAGS_STRIKE2 = 0x02
SNMP_FLAGS_STRIKE1 = 0x01
SNMPERR_SUCCESS = 0
SNMPERR_GENERR = -1
SNMPERR_BAD_LOCPORT = -2
SNMPERR_BAD_ADDRESS = -3
SNMPERR_BAD_SESSION = -4
SNMPERR_TOO_LONG = -5
SNMPERR_NO_SOCKET = -6
SNMPERR_V2_IN_V1 = -7
SNMPERR_V1_IN_V2 = -8
SNMPERR_BAD_REPEATERS = -9
SNMPERR_BAD_REPETITIONS = -10
SNMPERR_BAD_ASN1_BUILD = -11
SNMPERR_BAD_SENDTO = -12
SNMPERR_BAD_PARSE = -13
SNMPERR_BAD_VERSION = -14
SNMPERR_BAD_SRC_PARTY = -15
SNMPERR_BAD_DST_PARTY = -16
SNMPERR_BAD_CONTEXT = -17
SNMPERR_BAD_COMMUNITY = -18
SNMPERR_NOAUTH_DESPRIV = -19
SNMPERR_BAD_ACL = -20
SNMPERR_BAD_PARTY = -21
SNMPERR_ABORT = -22
SNMPERR_UNKNOWN_PDU = -23
SNMPERR_TIMEOUT = -24
SNMPERR_BAD_RECVFROM = -25
SNMPERR_BAD_ENG_ID = -26
SNMPERR_BAD_SEC_NAME = -27
SNMPERR_BAD_SEC_LEVEL = -28
SNMPERR_ASN_PARSE_ERR = -29
SNMPERR_UNKNOWN_SEC_MODEL = -30
SNMPERR_INVALID_MSG = -31
SNMPERR_UNKNOWN_ENG_ID = -32
SNMPERR_UNKNOWN_USER_NAME = -33
SNMPERR_UNSUPPORTED_SEC_LEVEL = -34
SNMPERR_AUTHENTICATION_FAILURE = -35
SNMPERR_NOT_IN_TIME_WINDOW = -36
SNMPERR_DECRYPTION_ERR = -37
SNMPERR_SC_GENERAL_FAILURE = -38
SNMPERR_SC_NOT_CONFIGURED = -39
SNMPERR_KT_NOT_AVAILABLE = -40
SNMPERR_UNKNOWN_REPORT = -41
SNMPERR_USM_GENERICERROR = -42
SNMPERR_USM_UNKNOWNSECURITYNAME = -43
SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL = -44
SNMPERR_USM_ENCRYPTIONERROR = -45
SNMPERR_USM_AUTHENTICATIONFAILURE = -46
SNMPERR_USM_PARSEERROR = -47
SNMPERR_USM_UNKNOWNENGINEID = -48
SNMPERR_USM_NOTINTIMEWINDOW = -49
SNMPERR_USM_DECRYPTIONERROR = -50
SNMPERR_NOMIB = -51
SNMPERR_RANGE = -52
SNMPERR_MAX_SUBID = -53
SNMPERR_BAD_SUBID = -54
SNMPERR_LONG_OID = -55
SNMPERR_BAD_NAME = -56
SNMPERR_VALUE = -57
SNMPERR_UNKNOWN_OBJID = -58
SNMPERR_NULL_PDU = -59
SNMPERR_NO_VARS = -60
SNMPERR_VAR_TYPE = -61
SNMPERR_MALLOC = -62
SNMPERR_KRB5 = -63
SNMPERR_PROTOCOL = -64
SNMPERR_OID_NONINCREASING = -65
SNMPERR_JUST_A_CONTEXT_PROBE = -66
SNMPERR_TRANSPORT_NO_CONFIG = -67
SNMPERR_TRANSPORT_CONFIG_ERROR = -68
SNMPERR_TLS_NO_CERTIFICATE = -69
SNMPERR_MAX = -69
NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE = 1
NETSNMP_CALLBACK_OP_TIMED_OUT = 2
NETSNMP_CALLBACK_OP_SEND_FAILED = 3
NETSNMP_CALLBACK_OP_CONNECT = 4
NETSNMP_CALLBACK_OP_DISCONNECT = 5
snmp_init_statistics = ()
STAT_SNMPUNKNOWNSECURITYMODELS = 0
STAT_SNMPINVALIDMSGS = 1
STAT_SNMPUNKNOWNPDUHANDLERS = 2
STAT_MPD_STATS_START = STAT_SNMPUNKNOWNSECURITYMODELS
STAT_MPD_STATS_END = STAT_SNMPUNKNOWNPDUHANDLERS
STAT_USMSTATSUNSUPPORTEDSECLEVELS = 3
STAT_USMSTATSNOTINTIMEWINDOWS = 4
STAT_USMSTATSUNKNOWNUSERNAMES = 5
STAT_USMSTATSUNKNOWNENGINEIDS = 6
STAT_USMSTATSWRONGDIGESTS = 7
STAT_USMSTATSDECRYPTIONERRORS = 8
STAT_USM_STATS_START = STAT_USMSTATSUNSUPPORTEDSECLEVELS
STAT_USM_STATS_END = STAT_USMSTATSDECRYPTIONERRORS
STAT_SNMPINPKTS = 9
STAT_SNMPOUTPKTS = 10
STAT_SNMPINBADVERSIONS = 11
STAT_SNMPINBADCOMMUNITYNAMES = 12
STAT_SNMPINBADCOMMUNITYUSES = 13
STAT_SNMPINASNPARSEERRS = 14
STAT_SNMPINTOOBIGS = 16
STAT_SNMPINNOSUCHNAMES = 17
STAT_SNMPINBADVALUES = 18
STAT_SNMPINREADONLYS = 19
STAT_SNMPINGENERRS = 20
STAT_SNMPINTOTALREQVARS = 21
STAT_SNMPINTOTALSETVARS = 22
STAT_SNMPINGETREQUESTS = 23
STAT_SNMPINGETNEXTS = 24
STAT_SNMPINSETREQUESTS = 25
STAT_SNMPINGETRESPONSES = 26
STAT_SNMPINTRAPS = 27
STAT_SNMPOUTTOOBIGS = 28
STAT_SNMPOUTNOSUCHNAMES = 29
STAT_SNMPOUTBADVALUES = 30
STAT_SNMPOUTGENERRS = 32
STAT_SNMPOUTGETREQUESTS = 33
STAT_SNMPOUTGETNEXTS = 34
STAT_SNMPOUTSETREQUESTS = 35
STAT_SNMPOUTGETRESPONSES = 36
STAT_SNMPOUTTRAPS = 37
STAT_SNMPSILENTDROPS = 39
STAT_SNMPPROXYDROPS = 40
STAT_SNMP_STATS_START = STAT_SNMPINPKTS
STAT_SNMP_STATS_END = STAT_SNMPPROXYDROPS
STAT_SNMPUNAVAILABLECONTEXTS = 41
STAT_SNMPUNKNOWNCONTEXTS = 42
STAT_TARGET_STATS_START = STAT_SNMPUNAVAILABLECONTEXTS
STAT_TARGET_STATS_END = STAT_SNMPUNKNOWNCONTEXTS
STAT_TSM_SNMPTSMINVALIDCACHES = 43
STAT_TSM_SNMPTSMINADEQUATESECURITYLEVELS = 44
STAT_TSM_SNMPTSMUNKNOWNPREFIXES = 45
STAT_TSM_SNMPTSMINVALIDPREFIXES = 46
STAT_TSM_STATS_START = STAT_TSM_SNMPTSMINVALIDCACHES
STAT_TSM_STATS_END = STAT_TSM_SNMPTSMINVALIDPREFIXES
STAT_TLSTM_SNMPTLSTMSESSIONOPENS = 47
STAT_TLSTM_SNMPTLSTMSESSIONCLIENTCLOSES = 48
STAT_TLSTM_SNMPTLSTMSESSIONOPENERRORS = 49
STAT_TLSTM_SNMPTLSTMSESSIONACCEPTS = 50
STAT_TLSTM_SNMPTLSTMSESSIONSERVERCLOSES = 51
STAT_TLSTM_SNMPTLSTMSESSIONNOSESSIONS = 52
STAT_TLSTM_SNMPTLSTMSESSIONINVALIDCLIENTCERTIFICATES = 53
STAT_TLSTM_SNMPTLSTMSESSIONUNKNOWNSERVERCERTIFICATE = 54
STAT_TLSTM_SNMPTLSTMSESSIONINVALIDSERVERCERTIFICATES = 55
STAT_TLSTM_SNMPTLSTMSESSIONINVALIDCACHES = 56
STAT_TLSTM_STATS_START = STAT_TLSTM_SNMPTLSTMSESSIONOPENS
STAT_TLSTM_STATS_END = STAT_TLSTM_SNMPTLSTMSESSIONINVALIDCACHES
NETSNMP_STAT_MAX_STATS = STAT_TLSTM_STATS_END + 1
MAX_STATS = NETSNMP_STAT_MAX_STATS
COMMUNITY_MAX_LEN = 256
SPRINT_MAX_LEN = 2560
NULL = 0
TRUE = 1
FALSE = 0
READ = 1
WRITE = 0
RESERVE1 = 0
RESERVE2 = 1
ACTION = 2
COMMIT = 3
FREE = 4
UNDO = 5
FINISHED_SUCCESS = 9
FINISHED_FAILURE = 10
NETSNMP_OLDAPI_RONLY = 0x1
NETSNMP_OLDAPI_RWRITE = 0x2
NETSNMP_OLDAPI_NOACCESS = 0x0000
RONLY = NETSNMP_OLDAPI_RONLY
RWRITE = NETSNMP_OLDAPI_RWRITE
NOACCESS = NETSNMP_OLDAPI_NOACCESS
ASN_IPADDRESS = ASN_APPLICATION | 0
ASN_COUNTER = ASN_APPLICATION | 1
ASN_GAUGE = ASN_APPLICATION | 2
ASN_UNSIGNED = ASN_APPLICATION | 2
ASN_TIMETICKS = ASN_APPLICATION | 3
ASN_OPAQUE = ASN_APPLICATION | 4
ASN_NSAP = ASN_APPLICATION | 5
ASN_COUNTER64 = ASN_APPLICATION | 6
ASN_UINTEGER = ASN_APPLICATION | 7
ASN_FLOAT = ASN_APPLICATION | 8
ASN_DOUBLE = ASN_APPLICATION | 9
ASN_INTEGER64 = ASN_APPLICATION | 10
ASN_UNSIGNED64 = ASN_APPLICATION | 11
FIRST_PASS = 1
LAST_PASS = 2
LOG_EMERG = 0
LOG_ALERT = 1
LOG_CRIT = 2
LOG_ERR = 3
LOG_WARNING = 4
LOG_NOTICE = 5
LOG_INFO = 6
LOG_DEBUG = 7
DEFAULT_LOG_ID = "net-snmp"
NETSNMP_LOGHANDLER_STDOUT = 1
NETSNMP_LOGHANDLER_STDERR = 2
NETSNMP_LOGHANDLER_FILE = 3
NETSNMP_LOGHANDLER_SYSLOG = 4
NETSNMP_LOGHANDLER_CALLBACK = 5
NETSNMP_LOGHANDLER_NONE = 6
NETSNMP_DS_MAX_IDS = 3
NETSNMP_DS_MAX_SUBIDS = 48
NETSNMP_DS_LIBRARY_ID = 0
NETSNMP_DS_APPLICATION_ID = 1
NETSNMP_DS_TOKEN_ID = 2
NETSNMP_DS_LIB_MIB_ERRORS = 0
NETSNMP_DS_LIB_SAVE_MIB_DESCRS = 1
NETSNMP_DS_LIB_MIB_COMMENT_TERM = 2
NETSNMP_DS_LIB_MIB_PARSE_LABEL = 3
NETSNMP_DS_LIB_DUMP_PACKET = 4
NETSNMP_DS_LIB_LOG_TIMESTAMP = 5
NETSNMP_DS_LIB_DONT_READ_CONFIGS = 6
NETSNMP_DS_LIB_DISABLE_CONFIG_LOAD = NETSNMP_DS_LIB_DONT_READ_CONFIGS
NETSNMP_DS_LIB_MIB_REPLACE = 7
NETSNMP_DS_LIB_PRINT_NUMERIC_ENUM = 8
NETSNMP_DS_LIB_PRINT_NUMERIC_OIDS = 9
NETSNMP_DS_LIB_DONT_BREAKDOWN_OIDS = 10
NETSNMP_DS_LIB_ALARM_DONT_USE_SIG = 11
NETSNMP_DS_LIB_PRINT_FULL_OID = 12
NETSNMP_DS_LIB_QUICK_PRINT = 13
NETSNMP_DS_LIB_RANDOM_ACCESS = 14
NETSNMP_DS_LIB_REGEX_ACCESS = 15
NETSNMP_DS_LIB_DONT_CHECK_RANGE = 16
NETSNMP_DS_LIB_NO_TOKEN_WARNINGS = 17
NETSNMP_DS_LIB_NUMERIC_TIMETICKS = 18
NETSNMP_DS_LIB_ESCAPE_QUOTES = 19
NETSNMP_DS_LIB_REVERSE_ENCODE = 20
NETSNMP_DS_LIB_PRINT_BARE_VALUE = 21
NETSNMP_DS_LIB_EXTENDED_INDEX = 22
NETSNMP_DS_LIB_PRINT_HEX_TEXT = 23
NETSNMP_DS_LIB_PRINT_UCD_STYLE_OID = 24
NETSNMP_DS_LIB_READ_UCD_STYLE_OID = 25
NETSNMP_DS_LIB_HAVE_READ_PREMIB_CONFIG = 26
NETSNMP_DS_LIB_HAVE_READ_CONFIG = 27
NETSNMP_DS_LIB_QUICKE_PRINT = 28
NETSNMP_DS_LIB_DONT_PRINT_UNITS = 29
NETSNMP_DS_LIB_NO_DISPLAY_HINT = 30
NETSNMP_DS_LIB_16BIT_IDS = 31
NETSNMP_DS_LIB_DONT_PERSIST_STATE = 32
NETSNMP_DS_LIB_2DIGIT_HEX_OUTPUT = 33
NETSNMP_DS_LIB_IGNORE_NO_COMMUNITY = 34
NETSNMP_DS_LIB_DISABLE_PERSISTENT_LOAD = 35
NETSNMP_DS_LIB_DISABLE_PERSISTENT_SAVE = 36
NETSNMP_DS_LIB_APPEND_LOGFILES = 37
NETSNMP_DS_LIB_NO_DISCOVERY = 38
NETSNMP_DS_LIB_TSM_USE_PREFIX = 39
NETSNMP_DS_LIB_DONT_LOAD_HOST_FILES = 40
NETSNMP_DS_LIB_DNSSEC_WARN_ONLY = 41
NETSNMP_DS_LIB_MAX_BOOL_ID = 48
NETSNMP_DS_LIB_MIB_WARNINGS = 0
NETSNMP_DS_LIB_SECLEVEL = 1
NETSNMP_DS_LIB_SNMPVERSION = 2
NETSNMP_DS_LIB_DEFAULT_PORT = 3
NETSNMP_DS_LIB_OID_OUTPUT_FORMAT = 4
NETSNMP_DS_LIB_PRINT_SUFFIX_ONLY = NETSNMP_DS_LIB_OID_OUTPUT_FORMAT
NETSNMP_DS_LIB_STRING_OUTPUT_FORMAT = 5
NETSNMP_DS_LIB_HEX_OUTPUT_LENGTH = 6
NETSNMP_DS_LIB_SERVERSENDBUF = 7
NETSNMP_DS_LIB_SERVERRECVBUF = 8
NETSNMP_DS_LIB_CLIENTSENDBUF = 9
NETSNMP_DS_LIB_CLIENTRECVBUF = 10
NETSNMP_DS_SSHDOMAIN_SOCK_PERM = 11
NETSNMP_DS_SSHDOMAIN_DIR_PERM = 12
NETSNMP_DS_SSHDOMAIN_SOCK_USER = 12
NETSNMP_DS_SSHDOMAIN_SOCK_GROUP = 13
NETSNMP_DS_LIB_TIMEOUT = 14
NETSNMP_DS_LIB_RETRIES = 15
NETSNMP_DS_LIB_MAX_INT_ID = 48
NETSNMP_DS_SNMP_VERSION_1 = 128
NETSNMP_DS_SNMP_VERSION_2c = 1
NETSNMP_DS_SNMP_VERSION_3 = 3
NETSNMP_DS_LIB_SECNAME = 0
NETSNMP_DS_LIB_CONTEXT = 1
NETSNMP_DS_LIB_PASSPHRASE = 2
NETSNMP_DS_LIB_AUTHPASSPHRASE = 3
NETSNMP_DS_LIB_PRIVPASSPHRASE = 4
NETSNMP_DS_LIB_OPTIONALCONFIG = 5
NETSNMP_DS_LIB_APPTYPE = 6
NETSNMP_DS_LIB_COMMUNITY = 7
NETSNMP_DS_LIB_PERSISTENT_DIR = 8
NETSNMP_DS_LIB_CONFIGURATION_DIR = 9
NETSNMP_DS_LIB_SECMODEL = 10
NETSNMP_DS_LIB_MIBDIRS = 11
NETSNMP_DS_LIB_OIDSUFFIX = 12
NETSNMP_DS_LIB_OIDPREFIX = 13
NETSNMP_DS_LIB_CLIENT_ADDR = 14
NETSNMP_DS_LIB_TEMP_FILE_PATTERN = 15
NETSNMP_DS_LIB_AUTHMASTERKEY = 16
NETSNMP_DS_LIB_PRIVMASTERKEY = 17
NETSNMP_DS_LIB_AUTHLOCALIZEDKEY = 18
NETSNMP_DS_LIB_PRIVLOCALIZEDKEY = 19
NETSNMP_DS_LIB_APPTYPES = 20
NETSNMP_DS_LIB_KSM_KEYTAB = 21
NETSNMP_DS_LIB_KSM_SERVICE_NAME = 22
NETSNMP_DS_LIB_X509_CLIENT_PUB = 23
NETSNMP_DS_LIB_X509_SERVER_PUB = 24
NETSNMP_DS_LIB_SSHTOSNMP_SOCKET = 25
NETSNMP_DS_LIB_CERT_EXTRA_SUBDIR = 26
NETSNMP_DS_LIB_HOSTNAME = 27
NETSNMP_DS_LIB_X509_CRL_FILE = 28
NETSNMP_DS_LIB_TLS_ALGORITMS = 29
NETSNMP_DS_LIB_TLS_LOCAL_CERT = 30
NETSNMP_DS_LIB_TLS_PEER_CERT = 31
NETSNMP_DS_LIB_SSH_USERNAME = 32
NETSNMP_DS_LIB_SSH_PUBKEY = 33
NETSNMP_DS_LIB_SSH_PRIVKEY = 34
NETSNMP_DS_LIB_MAX_STR_ID = 48
NETSNMP_NO_SUCH_PROCESS = -1
MAX_OID_LEN = 128
USM_AUTH_KU_LEN = 64
USM_PRIV_KU_LEN = 64

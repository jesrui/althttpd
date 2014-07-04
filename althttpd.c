/*
** A small, simple HTTP server.
**
** Features:
**
**     * Launched from inetd
**     * One process per request
**     * Deliver static content or run CGI
**     * Virtual sites based on the "Host:" property of the HTTP header
**     * Very small code base (1 file) to facilitate security auditing
**     * Simple setup - no configuration files to mess with.
** 
** This file implements a small and simple but secure and effective web
** server.  There are no frills.  Anything that could be reasonably
** omitted has been.
**
** Setup rules:
**
**    (1) Launch as root from inetd like this:
**
**            httpd -logfile logfile -root /home/www -user nobody
**
**        It will automatically chroot to /home/www and become user nobody.
**        The logfile name should be relative to the chroot jail.
**
**    (2) Directories of the form "*.website" (ex: www_hwaci_com.website)
**        contain content.  The directory is chosen based on HOST.  If no
**        HOST or the host directory is not found, "default.website" is used.
**
**    (3) Any file or directory whose name begins with "." or "-" is ignored.
**
**    (4) Characters other than a-zA-Z0-9_.,*~/ in the filename are translated
**        into _.  This is a defense against cross-site scripting attacks and
**        other mischief.
**
**    (5) Executable files are run as CGI.  All other files are delivered
**        as is.
**
**    (6) For SSL support use stunnel and add the -https 1 option on the
**        httpd command-line.
**
**    (7) If a file named "-auth" exists in the same directory as file to
**        be run as CGI or to be delivered, then it contains information
**        for HTTP Basic authorization.  See file format details below.
**
**
** Basic Authorization:
**
** If the file "-auth" exists in the same directory as the content file
** (for both static content and CGI) then it contains the information used
** for basic authorization.  The file format is as follows:
**
**    *  Blank lines and lines that begin with '#' are ignored
**    *  "http-redirect" forces a redirect to HTTPS if not there already
**    *  "https-only" disallows operation in HTTP
**    *  "user NAME LOGIN:PASSWORD" checks to see if LOGIN:PASSWORD 
**       authorization credentials are provided, and if so sets the
**       REMOTE_USER to NAME.
**    *  "realm TEXT" sets the realm to TEXT.
**
** There can be multiple "user" lines.  If no "user" line matches, the
** request fails with a 401 error.
*/
#include <stdio.h>
#include <ctype.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <time.h>
#include <sys/times.h>
#include <netdb.h>
#include <errno.h>
#include <sys/resource.h>
#ifdef linux
#include <sys/sendfile.h>
#endif
#include <assert.h>

/*
** Configure the server by setting the following macros and recompiling.
*/
#ifndef DEFAULT_PORT
#define DEFAULT_PORT "80"
#endif
#ifndef MAX_CONTENT_LENGTH
#define MAX_CONTENT_LENGTH 20000000
#endif

/*
** We record most of the state information as global variables.  This
** saves having to pass information to subroutines as parameters, and
** makes the executable smaller...
*/
static char *zRoot = 0;          /* Root directory of the website */
static char *zTmpNam = 0;        /* Name of a temporary file */
static char zTmpNamBuf[500];     /* Space to hold the temporary filename */
static char *zProtocol = 0;      /* The protocol being using by the browser */
static char *zMethod = 0;        /* The method.  Must be GET */
static char *zScript = 0;        /* The object to retrieve */
static char *zRealScript = 0;    /* The object to retrieve.  Same as zScript
                                 ** except might have "/index.html" appended */
static char *zHome = 0;          /* The directory containing content */
static char *zQueryString = 0;   /* The query string on the end of the name */
static char *zFile = 0;          /* The filename of the object to retrieve */
static int lenFile = 0;          /* Length of the zFile name */
static char *zDir = 0;           /* Name of the directory holding zFile */
static char *zPathInfo = 0;      /* Part of the pathname past the file */
static char *zAgent = 0;         /* What type if browser is making this query */
static char *zServerName = 0;    /* The name after the http:// */
static char *zServerPort = 0;    /* The port number */
static char *zCookie = 0;        /* Cookies reported with the request */
static char *zHttpHost = 0;      /* Name according to the web browser */
static char *zRealPort = 0;      /* The real TCP port when running as daemon */
static char *zRemoteAddr = 0;    /* IP address of the request */
static char *zReferer = 0;       /* Name of the page that refered to us */
static char *zAccept = 0;        /* What formats will be accepted */
static char *zContentLength = 0; /* Content length reported in the header */
static char *zContentType = 0;   /* Content type reported in the header */
static char *zQuerySuffix = 0;   /* The part of the URL after the first ? */
static char *zAuthType = 0;      /* Authorization type (basic or digest) */
static char *zAuthArg = 0;       /* Authorization values */
static char *zRemoteUser = 0;    /* REMOTE_USER set by authorization module */
static int nIn = 0;              /* Number of bytes of input */
static int nOut = 0;             /* Number of bytes of output */
static char zReplyStatus[4];     /* Reply status code */
static int statusSent = 0;       /* True after status line is sent */
static char *zLogFile = 0;       /* Log to this file */
static int debugFlag = 0;        /* True if being debugged */
static struct timeval beginTime; /* Time when this process starts */
static int closeConnection = 0;  /* True to send Connection: close in reply */
static int nRequest = 0;         /* Number of requests processed */
static int omitLog = 0;          /* Do not make logfile entries if true */
static int useHttps = 0;         /* True to use HTTPS: instead of HTTP: */
static char *zHttp = "http";     /* http or https */
static int useTimeout = 1;       /* True to use times */
static int standalone = 0;       /* Run as a standalone server (no inetd) */
static int ipv6Only = 0;         /* Use IPv6 only */
static int ipv4Only = 0;         /* Use IPv4 only */
static struct rusage priorSelf;  /* Previously report SELF time */
static struct rusage priorChild; /* Previously report CHILD time */

/*
** Double any double-quote characters in a string.
*/
static char *Escape(char *z){
  int i, j;
  int n;
  char c;
  char *zOut;
  for(i=0; (c=z[i])!=0 && c!='"'; i++){}
  if( c==0 ) return z;
  n = 1;
  for(i++; (c=z[i])!=0; i++){ if( c=='"' ) n++; }
  zOut = malloc( i+n+1 );
  if( zOut==0 ) return "";
  for(i=j=0; (c=z[i])!=0; i++){
    zOut[j++] = c;
    if( c=='"' ) zOut[j++] = c;
  }
  zOut[j] = 0;
  return zOut;
}

/*
** Convert a struct timeval into an integer number of milliseconds
*/
static int tvms(struct timeval *p){
  return (int)(p->tv_sec*1000000 + p->tv_usec);
}

/*
** Make an entry in the log file.  If the HTTP connection should be
** closed, then terminate this process.  Otherwise return.
*/
static void MakeLogEntry(int a){
  FILE *log;
  if( zTmpNam ){
    unlink(zTmpNam);
  }
  if( zLogFile && !omitLog ){
    struct timeval now;
    struct tm *pTm;
    struct rusage self, children;
    int waitStatus;
    char zDate[200];
    char *zRM = zRemoteUser ? zRemoteUser : "";

    if( zScript==0 ) zScript = "";
    if( zRealScript==0 ) zRealScript = "";
    if( zRemoteAddr==0 ) zRemoteAddr = "";
    if( zHttpHost==0 ) zHttpHost = "";
    if( zReferer==0 ) zReferer = "";
    if( zAgent==0 ) zAgent = "";
    gettimeofday(&now, 0);
    pTm = localtime(&now.tv_sec);
    strftime(zDate, sizeof(zDate), "%Y-%m-%d %H:%M:%S", pTm);
    waitpid(-1, &waitStatus, WNOHANG);
    getrusage(RUSAGE_SELF, &self);
    getrusage(RUSAGE_CHILDREN, &children);
    if( (log = fopen(zLogFile,"a"))!=0 ){
#ifdef COMBINED_LOG_FORMAT
      strftime(zDate, sizeof(zDate), "%d/%b/%Y:%H:%M:%S %z", pTm);
      fprintf(log, "%s - - [%s] \"%s %s %s\" %s %d \"%s\" \"%s\"\n",
              zRemoteAddr, zDate, zMethod, zScript, zProtocol,
              zReplyStatus, nOut, zReferer, zAgent);
#else
      strftime(zDate, sizeof(zDate), "%Y-%m-%d %H:%M:%S", pTm);
      /* Log record files:
      **  (1) Date and time
      **  (2) IP address
      **  (3) URL being accessed
      **  (4) Referer
      **  (5) Reply status
      **  (6) Bytes received
      **  (7) Bytes sent
      **  (8) Self user time
      **  (9) Self system time
      ** (10) Children user time
      ** (11) Children system time
      ** (12) Total wall-clock time
      ** (13) Request number for same TCP/IP connection
      ** (14) User agent
      ** (15) Remote user
      ** (16) Bytes of URL that correspond to the SCRIPT_NAME
      */
      fprintf(log,
        "%s,%s,\"%s://%s%s\",\"%s\","
           "%s,%d,%d,%d,%d,%d,%d,%d,%d,\"%s\",\"%s\",%d\n",
        zDate, zRemoteAddr, zHttp, Escape(zHttpHost), Escape(zScript),
        Escape(zReferer), zReplyStatus, nIn, nOut,
        tvms(&self.ru_utime) - tvms(&priorSelf.ru_utime),
        tvms(&self.ru_stime) - tvms(&priorSelf.ru_stime),
        tvms(&children.ru_utime) - tvms(&priorChild.ru_utime),
        tvms(&children.ru_stime) - tvms(&priorChild.ru_stime),
        tvms(&now) - tvms(&beginTime),
        nRequest, Escape(zAgent), Escape(zRM),
        (int)(strlen(zHttp)+strlen(zHttpHost)+strlen(zRealScript)+3)
      );
      priorSelf = self;
      priorChild = children;
      beginTime = now;
#endif
      fclose(log);
      nIn = nOut = 0;
    }
  }
  if( closeConnection ){
    exit(a);
  }
  statusSent = 0;
}

/*
** Allocate memory safely
*/
static char *SafeMalloc( int size ){
  char *p;

  p = (char*)malloc(size);
  if( p==0 ){
    strcpy(zReplyStatus, "998");
    MakeLogEntry(1);
    exit(1);
  }
  return p;
}

/*
** Set the value of environment variable zVar to zValue.
*/
static void SetEnv(const char *zVar, const char *zValue){
  char *z;
  int len;
  if( zValue==0 ) zValue="";
  len = strlen(zVar) + strlen(zValue) + 2;
  z = SafeMalloc(len);
  sprintf(z,"%s=%s",zVar,zValue);
  putenv(z);
}

/*
** Remove the first space-delimited token from a string and return
** a pointer to it.  Add a NULL to the string to terminate the token.
** Make *zLeftOver point to the start of the next token.
*/
static char *GetFirstElement(char *zInput, char **zLeftOver){
  char *zResult = 0;
  if( zInput==0 ){
    if( zLeftOver ) *zLeftOver = 0;
    return 0;
  }
  while( isspace(*zInput) ){ zInput++; }
  zResult = zInput;
  while( *zInput && !isspace(*zInput) ){ zInput++; }
  if( *zInput ){
    *zInput = 0;
    zInput++;
    while( isspace(*zInput) ){ zInput++; }
  }
  if( zLeftOver ){ *zLeftOver = zInput; }
  return zResult;
}

/*
** Make a copy of a string into memory obtained from malloc.
*/
static char *StrDup(const char *zSrc){
  char *zDest;
  int size;

  if( zSrc==0 ) return 0;
  size = strlen(zSrc) + 1;
  zDest = (char*)SafeMalloc( size );
  strcpy(zDest,zSrc);
  return zDest;
}
static char *StrAppend(char *zPrior, const char *zSep, const char *zSrc){
  char *zDest;
  int size;
  int n1, n2;

  if( zSrc==0 ) return 0;
  if( zPrior==0 ) return StrDup(zSrc);
  size = (n1=strlen(zSrc)) + (n2=strlen(zSep)) + strlen(zPrior) + 1;
  zDest = (char*)SafeMalloc( size );
  strcpy(zDest,zPrior);
  free(zPrior);
  strcpy(&zDest[n1],zSep);
  strcpy(&zDest[n1+n2],zSrc);
  return zDest;
}

/*
** Break a line at the first \n or \r character seen.
*/
static void RemoveNewline(char *z){
  if( z==0 ) return;
  while( *z && *z!='\n' && *z!='\r' ){ z++; }
  *z = 0;
}

/*
** Print a date tag in the header.  The name of the tag is zTag.
** The date is determined from the unix timestamp given.
*/
static int DateTag(const char *zTag, time_t t){
  struct tm *tm;
  char zDate[100];
  tm = gmtime(&t);
  strftime(zDate, sizeof(zDate), "%a, %d  %b %Y %H:%M:%S %z", tm);
  return printf("%s: %s\r\n", zTag, zDate);
}

/*
** Print the first line of a response followed by the server type.
*/
static void StartResponse(const char *zResultCode){
  time_t now;
  time(&now);
  if( statusSent ) return;
  nOut += printf("%s %s\r\n", zProtocol, zResultCode);
  strncpy(zReplyStatus, zResultCode, 3);
  zReplyStatus[3] = 0;
  if( zReplyStatus[0]>='4' ){
    closeConnection = 1;
  }
  if( closeConnection ){
    nOut += printf("Connection: close\r\n");
  }else{
    nOut += printf("Connection: keep-alive\r\n");
  }
  nOut += DateTag("Date", now);
  statusSent = 1;
}

/*
** Tell the client that there is no such document
*/
static void NotFound(int lineno){
  StartResponse("404 Not Found");
  nOut += printf(
    "Content-type: text/html\r\n"
    "\r\n"
    "<head><title lineno=\"%d\">Not Found</title></head>\n"
    "<body><h1>Document Not Found</h1>\n"
    "The document %s is not available on this server\n"
    "</body>\n", lineno, zScript);
  MakeLogEntry(0);
  exit(0);
}

/*
** Tell the client that they are not welcomed here.
*/
static void Forbidden(void){
  StartResponse("403 Forbidden");
  nOut += printf(
    "Content-type: text/plain\r\n"
    "\r\n"
    "Access denied\n"
  );
  closeConnection = 1;
  MakeLogEntry(0);
  exit(0);
}

/*
** Tell the client that authorization is required to access the
** document.
*/
static void NotAuthorized(const char *zRealm){
  StartResponse("401 Authorization Required");
  nOut += printf(
    "WWW-Authenticate: Basic realm=\"%s\"\r\n"
    "Content-type: text/html\r\n"
    "\r\n"
    "<head><title>Not Authorized</title></head>\n"
    "<body><h1>401 Not Authorized</h1>\n"
    "A login and password are required for this document\n"
    "</body>\n", zRealm);
  MakeLogEntry(0);
}

/*
** Tell the client that there is an error in the script.
*/
static void CgiError(void){
  StartResponse("500 Error");
  nOut += printf(
    "Content-type: text/html\r\n"
    "\r\n"
    "<head><title>CGI Program Error</title></head>\n"
    "<body><h1>CGI Program Error</h1>\n"
    "The CGI program %s generated an error\n"
    "</body>\n", zScript);
  MakeLogEntry(0);
  exit(0);
}

/*
** This is called if we timeout.
*/
static void Timeout(int NotUsed){
  (void)NotUsed;
  if( !debugFlag ){
    if( zScript && zScript[0] ){
      strcpy(zReplyStatus, "999");
      MakeLogEntry(0);
    }
    exit(0);
  }
}

/*
** Tell the client that there is an error in the script.
*/
static void CgiScriptWritable(void){
  StartResponse("500 CGI Configuration Error");
  nOut += printf(
    "Content-type: text/plain\r\n"
    "\r\n"
    "The CGI program %s is writable by users other than its owner.\n",
    zRealScript);
  MakeLogEntry(0);
  exit(0);       
}

/*
** Tell the client that the server malfunctioned.
*/
static void Malfunction(int linenum, const char *zFormat, ...){
  va_list ap;
  va_start(ap, zFormat);
  StartResponse("500 Server Malfunction");
  nOut += printf(
    "Content-type: text/plain\r\n"
    "\r\n"
    "Web server malfunctioned; error number %d\n\n", linenum);
  if( zFormat ){
    nOut += vprintf(zFormat, ap);
  }
  MakeLogEntry(0);
  exit(0);       
}

/*
** Do a server redirect to the document specified.  The document
** name not contain scheme or network location or the query string.
** It will be just the path.
*/
static void Redirect(const char *zPath, int finish){
  StartResponse("302 Temporary Redirect");
  if( zServerPort==0 || zServerPort[0]==0 || strcmp(zServerPort,"80")==0 ){
    nOut += printf("Location: %s://%s%s%s\r\n",
                   zHttp, zServerName, zPath, zQuerySuffix);
  }else{
    nOut += printf("Location: %s://%s:%s%s%s\r\n",
                   zHttp, zServerName, zServerPort, zPath, zQuerySuffix);
  }
  if( finish ){
    nOut += printf("Content-length: 0\r\n");
    nOut += printf("\r\n");
    MakeLogEntry(0);
  }
  fflush(stdout);
}

/*
** This function treats its input as a base-64 string and returns the
** decoded value of that string.  Characters of input that are not
** valid base-64 characters (such as spaces and newlines) are ignored.
*/
void Decode64(char *z64){
  char *zData;
  int n64;
  int i, j;
  int a, b, c, d;
  static int isInit = 0;
  static int trans[128];
  static unsigned char zBase[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  if( !isInit ){
    for(i=0; i<128; i++){ trans[i] = 0; }
    for(i=0; zBase[i]; i++){ trans[zBase[i] & 0x7f] = i; }
    isInit = 1;
  }
  n64 = strlen(z64);
  while( n64>0 && z64[n64-1]=='=' ) n64--;
  zData = z64;
  for(i=j=0; i+3<n64; i+=4){
    a = trans[z64[i] & 0x7f];
    b = trans[z64[i+1] & 0x7f];
    c = trans[z64[i+2] & 0x7f];
    d = trans[z64[i+3] & 0x7f];
    zData[j++] = ((a<<2) & 0xfc) | ((b>>4) & 0x03);
    zData[j++] = ((b<<4) & 0xf0) | ((c>>2) & 0x0f);
    zData[j++] = ((c<<6) & 0xc0) | (d & 0x3f);
  }
  if( i+2<n64 ){
    a = trans[z64[i] & 0x7f];
    b = trans[z64[i+1] & 0x7f];
    c = trans[z64[i+2] & 0x7f];
    zData[j++] = ((a<<2) & 0xfc) | ((b>>4) & 0x03);
    zData[j++] = ((b<<4) & 0xf0) | ((c>>2) & 0x0f);
  }else if( i+1<n64 ){
    a = trans[z64[i] & 0x7f];
    b = trans[z64[i+1] & 0x7f];
    zData[j++] = ((a<<2) & 0xfc) | ((b>>4) & 0x03);
  }
  zData[j] = 0;
}

/*
** Check to see if basic authorization credentials are provided for
** the user according to the information in zAuthFile.  Return true
** if authorized.  Return false if not authorized.
**
** File format:
**
**    *  Blank lines and lines that begin with '#' are ignored
**    *  "http-redirect" forces a redirect to HTTPS if not there already
**    *  "https-only" disallows operation in HTTP
**    *  "user NAME LOGIN:PASSWORD" checks to see if LOGIN:PASSWORD 
**       authorization credentials are provided, and if so sets the
**       REMOTE_USER to NAME.
**    *  "realm TEXT" sets the realm to TEXT.
*/
static int CheckBasicAuthorization(const char *zAuthFile){
  FILE *in;
  char *zRealm = "unknown realm";
  char *zLoginPswd;
  char *zName;
  char zLine[2000];

  in = fopen(zAuthFile, "r");
  if( in==0 ){
    NotFound(__LINE__);
    return 0;
  }
  if( zAuthArg ) Decode64(zAuthArg);
  while( fgets(zLine, sizeof(zLine), in) ){
    char *zFieldName;
    char *zVal;

    zFieldName = GetFirstElement(zLine,&zVal);
    if( zFieldName==0 || *zFieldName==0 ) continue;
    if( zFieldName[0]=='#' ) continue;
    RemoveNewline(zVal);
    if( strcmp(zFieldName, "realm")==0 ){
      zRealm = StrDup(zVal);
    }else if( strcmp(zFieldName,"user")==0 ){
      if( zAuthArg==0 ) continue;
      zName = GetFirstElement(zVal, &zVal);
      zLoginPswd = GetFirstElement(zVal, &zVal);
      if( zLoginPswd==0 ) continue;
      if( zAuthArg && strcmp(zAuthArg,zLoginPswd)==0 ){
        zRemoteUser = StrDup(zName);
        fclose(in);
        return 1;
      }
    }else if( strcmp(zFieldName,"https-only")==0 ){
      if( !useHttps ){
        NotFound(__LINE__);
        fclose(in);
        return 0;
      }
    }else if( strcmp(zFieldName,"http-redirect")==0 ){
      if( !useHttps ){
        zHttp = "https";
        sprintf(zLine, "%s%s", zScript, zPathInfo);
        Redirect(zLine, 1);
        fclose(in);
        return 0;
      }
    }else{
      NotFound(__LINE__);
      fclose(in);
      return 0;
    }
  }
  fclose(in);
  NotAuthorized(zRealm);
  return 0;
}

/*
** Guess the mime-type of a document based on its name.
*/
const char *GetMimeType(const char *zName, int nName){
  const char *z;
  int i;
  int first, last;
  int len;
  char zSuffix[20];

  /* A table of mimetypes based on file suffixes. 
  ** Suffixes must be in sorted order so that we can do a binary
  ** search to find the mime-type
  */
  static const struct {
    const char *zSuffix;       /* The file suffix */
    int size;                  /* Length of the suffix */
    const char *zMimetype;     /* The corresponding mimetype */
  } aMime[] = {
    { "ai",         2, "application/postscript"            },
    { "aif",        3, "audio/x-aiff"                      },
    { "aifc",       4, "audio/x-aiff"                      },
    { "aiff",       4, "audio/x-aiff"                      },
    { "arj",        3, "application/x-arj-compressed"      },
    { "asc",        3, "text/plain"                        },
    { "asf",        3, "video/x-ms-asf"                    },
    { "asx",        3, "video/x-ms-asx"                    },
    { "au",         2, "audio/ulaw"                        },
    { "avi",        3, "video/x-msvideo"                   },
    { "bat",        3, "application/x-msdos-program"       },
    { "bcpio",      5, "application/x-bcpio"               },
    { "bin",        3, "application/octet-stream"          },
    { "c",          1, "text/plain"                        },
    { "cc",         2, "text/plain"                        },
    { "ccad",       4, "application/clariscad"             },
    { "cdf",        3, "application/x-netcdf"              },
    { "class",      5, "application/octet-stream"          },
    { "cod",        3, "application/vnd.rim.cod"           },
    { "com",        3, "application/x-msdos-program"       },
    { "cpio",       4, "application/x-cpio"                },
    { "cpt",        3, "application/mac-compactpro"        },
    { "csh",        3, "application/x-csh"                 },
    { "css",        3, "text/css"                          },
    { "dcr",        3, "application/x-director"            },
    { "deb",        3, "application/x-debian-package"      },
    { "dir",        3, "application/x-director"            },
    { "dl",         2, "video/dl"                          },
    { "dms",        3, "application/octet-stream"          },
    { "doc",        3, "application/msword"                },
    { "drw",        3, "application/drafting"              },
    { "dvi",        3, "application/x-dvi"                 },
    { "dwg",        3, "application/acad"                  },
    { "dxf",        3, "application/dxf"                   },
    { "dxr",        3, "application/x-director"            },
    { "eps",        3, "application/postscript"            },
    { "etx",        3, "text/x-setext"                     },
    { "exe",        3, "application/octet-stream"          },
    { "ez",         2, "application/andrew-inset"          },
    { "f",          1, "text/plain"                        },
    { "f90",        3, "text/plain"                        },
    { "fli",        3, "video/fli"                         },
    { "flv",        3, "video/flv"                         },
    { "gif",        3, "image/gif"                         },
    { "gl",         2, "video/gl"                          },
    { "gtar",       4, "application/x-gtar"                },
    { "gz",         2, "application/x-gzip"                },
    { "hdf",        3, "application/x-hdf"                 },
    { "hh",         2, "text/plain"                        },
    { "hqx",        3, "application/mac-binhex40"          },
    { "h",          1, "text/plain"                        },
    { "htm",        3, "text/html; charset=utf-8"          },
    { "html",       4, "text/html; charset=utf-8"          },
    { "ice",        3, "x-conference/x-cooltalk"           },
    { "ief",        3, "image/ief"                         },
    { "iges",       4, "model/iges"                        },
    { "igs",        3, "model/iges"                        },
    { "ips",        3, "application/x-ipscript"            },
    { "ipx",        3, "application/x-ipix"                },
    { "jad",        3, "text/vnd.sun.j2me.app-descriptor"  },
    { "jar",        3, "application/java-archive"          },
    { "jpeg",       4, "image/jpeg"                        },
    { "jpe",        3, "image/jpeg"                        },
    { "jpg",        3, "image/jpeg"                        },
    { "js",         2, "application/x-javascript"          },
    { "kar",        3, "audio/midi"                        },
    { "latex",      5, "application/x-latex"               },
    { "lha",        3, "application/octet-stream"          },
    { "lsp",        3, "application/x-lisp"                },
    { "lzh",        3, "application/octet-stream"          },
    { "m",          1, "text/plain"                        },
    { "m3u",        3, "audio/x-mpegurl"                   },
    { "man",        3, "application/x-troff-man"           },
    { "me",         2, "application/x-troff-me"            },
    { "mesh",       4, "model/mesh"                        },
    { "mid",        3, "audio/midi"                        },
    { "midi",       4, "audio/midi"                        },
    { "mif",        3, "application/x-mif"                 },
    { "mime",       4, "www/mime"                          },
    { "movie",      5, "video/x-sgi-movie"                 },
    { "mov",        3, "video/quicktime"                   },
    { "mp2",        3, "audio/mpeg"                        },
    { "mp2",        3, "video/mpeg"                        },
    { "mp3",        3, "audio/mpeg"                        },
    { "mpeg",       4, "video/mpeg"                        },
    { "mpe",        3, "video/mpeg"                        },
    { "mpga",       4, "audio/mpeg"                        },
    { "mpg",        3, "video/mpeg"                        },
    { "ms",         2, "application/x-troff-ms"            },
    { "msh",        3, "model/mesh"                        },
    { "nc",         2, "application/x-netcdf"              },
    { "oda",        3, "application/oda"                   },
    { "ogg",        3, "application/ogg"                   },
    { "ogm",        3, "application/ogg"                   },
    { "pbm",        3, "image/x-portable-bitmap"           },
    { "pdb",        3, "chemical/x-pdb"                    },
    { "pdf",        3, "application/pdf"                   },
    { "pgm",        3, "image/x-portable-graymap"          },
    { "pgn",        3, "application/x-chess-pgn"           },
    { "pgp",        3, "application/pgp"                   },
    { "pl",         2, "application/x-perl"                },
    { "pm",         2, "application/x-perl"                },
    { "png",        3, "image/png"                         },
    { "pnm",        3, "image/x-portable-anymap"           },
    { "pot",        3, "application/mspowerpoint"          },
    { "ppm",        3, "image/x-portable-pixmap"           },
    { "pps",        3, "application/mspowerpoint"          },
    { "ppt",        3, "application/mspowerpoint"          },
    { "ppz",        3, "application/mspowerpoint"          },
    { "pre",        3, "application/x-freelance"           },
    { "prt",        3, "application/pro_eng"               },
    { "ps",         2, "application/postscript"            },
    { "qt",         2, "video/quicktime"                   },
    { "ra",         2, "audio/x-realaudio"                 },
    { "ram",        3, "audio/x-pn-realaudio"              },
    { "rar",        3, "application/x-rar-compressed"      },
    { "ras",        3, "image/cmu-raster"                  },
    { "ras",        3, "image/x-cmu-raster"                },
    { "rgb",        3, "image/x-rgb"                       },
    { "rm",         2, "audio/x-pn-realaudio"              },
    { "roff",       4, "application/x-troff"               },
    { "rpm",        3, "audio/x-pn-realaudio-plugin"       },
    { "rtf",        3, "application/rtf"                   },
    { "rtf",        3, "text/rtf"                          },
    { "rtx",        3, "text/richtext"                     },
    { "scm",        3, "application/x-lotusscreencam"      },
    { "set",        3, "application/set"                   },
    { "sgml",       4, "text/sgml"                         },
    { "sgm",        3, "text/sgml"                         },
    { "sh",         2, "application/x-sh"                  },
    { "shar",       4, "application/x-shar"                },
    { "silo",       4, "model/mesh"                        },
    { "sit",        3, "application/x-stuffit"             },
    { "skd",        3, "application/x-koan"                },
    { "skm",        3, "application/x-koan"                },
    { "skp",        3, "application/x-koan"                },
    { "skt",        3, "application/x-koan"                },
    { "smi",        3, "application/smil"                  },
    { "smil",       4, "application/smil"                  },
    { "snd",        3, "audio/basic"                       },
    { "sol",        3, "application/solids"                },
    { "spl",        3, "application/x-futuresplash"        },
    { "src",        3, "application/x-wais-source"         },
    { "step",       4, "application/STEP"                  },
    { "stl",        3, "application/SLA"                   },
    { "stp",        3, "application/STEP"                  },
    { "sv4cpio",    7, "application/x-sv4cpio"             },
    { "sv4crc",     6, "application/x-sv4crc"              },
    { "swf",        3, "application/x-shockwave-flash"     },
    { "t",          1, "application/x-troff"               },
    { "tar",        3, "application/x-tar"                 },
    { "tcl",        3, "application/x-tcl"                 },
    { "tex",        3, "application/x-tex"                 },
    { "texi",       4, "application/x-texinfo"             },
    { "texinfo",    7, "application/x-texinfo"             },
    { "tgz",        3, "application/x-tar-gz"              },
    { "tiff",       4, "image/tiff"                        },
    { "tif",        3, "image/tiff"                        },
    { "tr",         2, "application/x-troff"               },
    { "tsi",        3, "audio/TSP-audio"                   },
    { "tsp",        3, "application/dsptype"               },
    { "tsv",        3, "text/tab-separated-values"         },
    { "txt",        3, "text/plain"                        },
    { "unv",        3, "application/i-deas"                },
    { "ustar",      5, "application/x-ustar"               },
    { "vcd",        3, "application/x-cdlink"              },
    { "vda",        3, "application/vda"                   },
    { "viv",        3, "video/vnd.vivo"                    },
    { "vivo",       4, "video/vnd.vivo"                    },
    { "vrml",       4, "model/vrml"                        },
    { "wav",        3, "audio/x-wav"                       },
    { "wax",        3, "audio/x-ms-wax"                    },
    { "wiki",       4, "application/x-fossil-wiki"         },
    { "wma",        3, "audio/x-ms-wma"                    },
    { "wmv",        3, "video/x-ms-wmv"                    },
    { "wmx",        3, "video/x-ms-wmx"                    },
    { "wrl",        3, "model/vrml"                        },
    { "wvx",        3, "video/x-ms-wvx"                    },
    { "xbm",        3, "image/x-xbitmap"                   },
    { "xlc",        3, "application/vnd.ms-excel"          },
    { "xll",        3, "application/vnd.ms-excel"          },
    { "xlm",        3, "application/vnd.ms-excel"          },
    { "xls",        3, "application/vnd.ms-excel"          },
    { "xlw",        3, "application/vnd.ms-excel"          },
    { "xml",        3, "text/xml"                          },
    { "xpm",        3, "image/x-xpixmap"                   },
    { "xwd",        3, "image/x-xwindowdump"               },
    { "xyz",        3, "chemical/x-pdb"                    },
    { "zip",        3, "application/zip"                   },
  };

  for(i=nName-1; i>0 && zName[i]!='.'; i--){}
  z = &zName[i+1];
  len = nName - i;
  if( len<(int)sizeof(zSuffix)-1 ){
    strcpy(zSuffix, z);
    for(i=0; zSuffix[i]; i++) zSuffix[i] = tolower(zSuffix[i]);
    first = 0;
    last = sizeof(aMime)/sizeof(aMime[0]);
    while( first<=last ){
      int c;
      i = (first+last)/2;
      c = strcmp(zSuffix, aMime[i].zSuffix);
      if( c==0 ) return aMime[i].zMimetype;
      if( c<0 ){
        last = i-1;
      }else{
        first = i+1;
      }
    }
  }
  return "application/octet-stream";
}

/*
** The following table contains 1 for all characters that are permitted in
** the part of the URL before the query parameters and fragment.
**
** Allowed characters:  0-9 a-z A-Z ,-./:_~
**
** Disallowed characters include:  !"#$%&'()*+;<=>?[\]^{|}
*/
static const char allowedInName[] = {
      /*  x0  x1  x2  x3  x4  x5  x6  x7  x8  x9  xa  xb  xc  xd  xe  xf */
/* 0x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* 1x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* 2x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  1,  1,  1,
/* 3x */   1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  0,  0,
/* 4x */   0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
/* 5x */   1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  0,  1,
/* 6x */   0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
/* 7x */   1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  1,  0,
};

/*
** Count the number of "/" characters in a string.
*/
static int countSlashes(const char *z){
  int n = 0;
  while( *z ) if( *(z++)=='/' ) n++;
  return n;
}

/*
** This routine processes a single HTTP request on standard input and
** sends the reply to standard output.  If the argument is 1 it means
** that we are should close the socket without processing additional
** HTTP requests after the current request finishes.  0 means we are
** allowed to keep the connection open and to process additional requests.
** This routine may choose to close the connection even if the argument
** is 0.
** 
** If the connection should be closed, this routine calls exit() and
** thus never returns.  If this routine does return it means that another
** HTTP request may appear on the wire.
*/
void ProcessOneRequest(int forceClose){
  int i, c;
  char *z;                  /* Used to parse up a string */
  struct stat statbuf;      /* Information about the file to be retrieved */
  FILE *in;                 /* For reading from CGI scripts */
  char zLine[1000];         /* A buffer for input lines or forming names */

  /* Change directories to the root of the HTTP filesystem
  */
  if( chdir(zRoot[0] ? zRoot : "/")!=0 ){
    char zBuf[1000];
    Malfunction(__LINE__, "cannot chdir to [%s] from [%s]",
         zRoot, getcwd(zBuf,999));
  }
  nRequest++;

  /*
  ** We must receive a complete header within 15 seconds
  */
  signal(SIGALRM, Timeout);
  if( useTimeout ) alarm(15);

  /* Get the first line of the request and parse out the
  ** method, the script and the protocol.
  */
  if( fgets(zLine,sizeof(zLine),stdin)==0 ){
    exit(0);
  }
  omitLog = 0;
  nIn += strlen(zLine);
  zMethod = StrDup(GetFirstElement(zLine,&z));
  zRealScript = zScript = StrDup(GetFirstElement(z,&z));
  zProtocol = StrDup(GetFirstElement(z,&z));
  if( zProtocol==0 || strncmp(zProtocol,"HTTP/",5)!=0 || strlen(zProtocol)!=8 ){
    StartResponse("400 Bad Request");
    nOut += printf(
      "Content-type: text/plain\r\n"
      "\r\n"
      "This server does not understand the requested protocol\n"
    );
    MakeLogEntry(0);
    exit(0);
  }
  if( zScript[0]==0 ) NotFound(__LINE__);
  if( forceClose ){
    closeConnection = 1;
  }else if( zProtocol[5]<'1' || zProtocol[7]<'1' ){
    closeConnection = 1;
  }

  /* This very simple server only understands the GET, POST
  ** and HEAD methods
  */
  if( strcmp(zMethod,"GET")!=0 && strcmp(zMethod,"POST")!=0
       && strcmp(zMethod,"HEAD")!=0 ){
    StartResponse("501 Not Implemented");
    nOut += printf(
      "Content-type: text/plain\r\n"
      "\r\n"
      "The %s method is not implemented on this server.\n",
      zMethod);
    MakeLogEntry(0);
    exit(0);
  }

  /* Get all the optional fields that follow the first line.
  */
  zCookie = 0;
  zAuthType = 0;
  zRemoteUser = 0;
  zReferer = 0;
  while( fgets(zLine,sizeof(zLine),stdin) ){
    char *zFieldName;
    char *zVal;

    nIn += strlen(zLine);
    zFieldName = GetFirstElement(zLine,&zVal);
    if( zFieldName==0 || *zFieldName==0 ) break;
    RemoveNewline(zVal);
    if( strcasecmp(zFieldName,"User-Agent:")==0 ){
      zAgent = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Accept:")==0 ){
      zAccept = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Content-length:")==0 ){
      zContentLength = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Content-type:")==0 ){
      zContentType = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Referer:")==0 ){
      zReferer = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Cookie:")==0 ){
      zCookie = StrAppend(zCookie,"; ",zVal);
    }else if( strcasecmp(zFieldName,"Connection:")==0 ){
      if( strcasecmp(zVal,"close")==0 ){
        closeConnection = 1;
      }else if( !forceClose && strcasecmp(zVal, "keep-alive")==0 ){
        closeConnection = 0;
      }
    }else if( strcasecmp(zFieldName,"Host:")==0 ){
      int inSquare = 0;
      char c;
      zHttpHost = StrDup(zVal);
      zServerPort = zServerName = StrDup(zHttpHost);
      while( zServerPort && (c = *zServerPort)!=0
              && (c!=':' || inSquare) ){
        if( c=='[' ) inSquare = 1;
        if( c==']' ) inSquare = 0;
        zServerPort++;
      }
      if( zServerPort && *zServerPort ){
        *zServerPort = 0;
        zServerPort++;
      }
      if( zRealPort ){
        zServerPort = StrDup(zRealPort);
      }
    }else if( strcasecmp(zFieldName,"Authorization:")==0 ){
      zAuthType = GetFirstElement(StrDup(zVal), &zAuthArg);
    }
  }

  /* Disallow referring from certain clients */
  if( zAgent ){
    if( strstr(zAgent, "Windows_9")!=0
     || strstr(zAgent, "Download_Master")!=0
     || strstr(zAgent, "Ezooms/")!=0
   /*|| strstr(zAgent, "bingbot")!=0*/
     || strstr(zAgent, "AhrefsBot")!=0
    ){
      Forbidden();
    }
  }
#if 0
  if( zReferer ){
    static const char *azDisallow[] = {
      "skidrowcrack.com",
      "hoshiyuugi.tistory.com",
      "skidrowgames.net",
    };
    int i;
    for(i=0; i<sizeof(azDisallow)/sizeof(azDisallow[0]); i++){
      if( strstr(zReferer, azDisallow[i])!=0 ) NotFound(__LINE__);
    }
  }
#endif

  /* Make an extra effort to get a valid server name and port number.
  ** Only Netscape provides this information.  If the browser is
  ** Internet Explorer, then we have to find out the information for
  ** ourselves.
  */
  if( zServerName==0 ){
    zServerName = SafeMalloc( 100 );
    gethostname(zServerName,100);
  }
  if( zServerPort==0 || *zServerPort==0 ){
    zServerPort = DEFAULT_PORT;
  }

  /* Remove the query string from the end of the requested file.
  */
  for(z=zScript; *z && *z!='?'; z++){}
  if( *z=='?' ){
    zQuerySuffix = StrDup(z);
    *z = 0;
  }else{
    zQuerySuffix = "";
  }
  zQueryString = *zQuerySuffix ? &zQuerySuffix[1] : zQuerySuffix;

  /* Create a file to hold the POST query data, if any.  We have to
  ** do it this way.  We can't just pass the file descriptor down to
  ** the child process because the fgets() function may have already
  ** read part of the POST data into its internal buffer.
  */
  if( zMethod[0]=='P' && zContentLength!=0 ){
    int len = atoi(zContentLength);
    FILE *out;
    char *zBuf;
    int n;

    if( len>MAX_CONTENT_LENGTH ){
      StartResponse("500 Request too large");
      nOut += printf(
        "Content-type: text/plain\r\n"
        "\r\n"
        "Too much POST data\n"
      );
      MakeLogEntry(0);
      exit(0);
    }
    sprintf(zTmpNamBuf, "/tmp/-post-data-XXXXXX");
    zTmpNam = zTmpNamBuf;
    mkstemp(zTmpNam);
    out = fopen(zTmpNam,"w");
    if( out==0 ){
      StartResponse("500 Cannot create /tmp file");
      nOut += printf(
        "Content-type: text/plain\r\n"
        "\r\n"
        "Could not open \"%s\" for writing\n", zTmpNam
      );
      MakeLogEntry(0);
      exit(0);
    }
    zBuf = SafeMalloc( len );
    if( useTimeout ) alarm(15 + len/2000);
    n = fread(zBuf,1,len,stdin);
    nIn += n;
    fwrite(zBuf,1,n,out);
    free(zBuf);
    fclose(out);
  }

  /* Make sure the running time is not too great */
  if( useTimeout ) alarm(10);

  /* Convert all unusual characters in the script name into "_".
  **
  ** This is a defense against various attacks, XSS attacks in particular.
  */
  for(z=zScript; *z; z++){
    unsigned char c = *(unsigned char*)z;
    if( (c&0x80)!=0 || !allowedInName[c] ){
      *z = '_';
      if( c=='%' && z[1]!=0 && z[2]!=0 ){
        for(i=3; (z[i-2] = z[i])!=0; i++){}
      }
    }
  }

  /* Don't allow "/." or "/-" to to occur anywhere in the entity name.
  ** This prevents attacks involving ".." and also allows us to create
  ** files and directories whose names begin with "-" which are invisible
  ** to the webserver.
  */
  for(z=zScript; *z; z++){
    if( *z=='/' && (z[1]=='.' || z[1]=='-') ){
       NotFound(__LINE__);
    }
  }

  /* Figure out what the root of the filesystem should be.  If the
  ** HTTP_HOST parameter exists (stored in zHttpHost) then remove the
  ** port number from the end (if any), convert all characters to lower
  ** case, and convert all "." to "_".  Then try to find a directory
  ** with that name and the extension .website.  If not found, look
  ** for "default.website".
  */
  if( zScript[0]!='/' ) NotFound(__LINE__);
  if( strlen(zRoot)+40 >= sizeof(zLine) ) NotFound(__LINE__);
  if( zHttpHost==0 || zHttpHost[0]==0 ){
    NotFound(__LINE__);
  }else if( strlen(zHttpHost)+strlen(zRoot)+10 >= sizeof(zLine) ){
    NotFound(__LINE__);
  }else{
    sprintf(zLine, "%s/%s", zRoot, zHttpHost);
    for(i=strlen(zRoot)+1; zLine[i] && zLine[i]!=':'; i++){
      int c = zLine[i];
      if( !isalnum(c) ){
        zLine[i] = '_';
      }else if( isupper(c) ){
        zLine[i] = tolower(c);
      }
    }
    strcpy(&zLine[i], ".website");
  }
  if( stat(zLine,&statbuf) || !S_ISDIR(statbuf.st_mode) ){
    sprintf(zLine, "%s/default.website", zRoot);
    if( stat(zLine,&statbuf) || !S_ISDIR(statbuf.st_mode) ){
      if( standalone ){
        sprintf(zLine, "%s", zRoot);
      }else{
        NotFound(__LINE__);
      }
    }
  }
  zHome = StrDup(zLine);

  /* Change directories to the root of the HTTP filesystem
  */
  if( chdir(zHome)!=0 ){
    char zBuf[1000];
    Malfunction(__LINE__, "cannot chdir to [%s] from [%s]",
         zHome, getcwd(zBuf,999));
  }

  /* Locate the file in the filesystem.  We might have to append
  ** the name "index.html" in order to find it.  Any excess path
  ** information is put into the zPathInfo variable.
  */
  zLine[0] = '.';
  i = 0;
  while( zScript[i] ){
    while( zScript[i] && zScript[i]!='/' ){
      zLine[i+1] = zScript[i];
      i++;
    }
    zLine[i+1] = 0;
    if( stat(zLine,&statbuf)!=0 ){
      int stillSearching = 1;
      while( stillSearching && i>0 ){
        while( i>0 && zLine[i]!='/' ){ i--; }
        strcpy(&zLine[i], "/not-found.html");
        if( stat(zLine,&statbuf)==0 && S_ISREG(statbuf.st_mode)
            && access(zLine,R_OK)==0 ){
          zRealScript = StrDup(&zLine[1]);
          Redirect(zRealScript, 1);
          return;
        }else{
          i--;
        }
      }
      if( stillSearching ) NotFound(__LINE__);
      break;
    }
    if( S_ISREG(statbuf.st_mode) ){
      if( access(zLine,R_OK) ){
        NotFound(__LINE__);
      }
      zRealScript = StrDup(&zLine[1]);
      break;
    }
    if( zScript[i]==0 || zScript[i+1]==0 ){
      strcpy(&zLine[i+1],"/index.html");
      if( stat(zLine,&statbuf)!=0 || !S_ISREG(statbuf.st_mode) 
      || access(zLine,R_OK) ){
        strcpy(&zLine[i+1],"/index.cgi");
        if( stat(zLine,&statbuf)!=0 || !S_ISREG(statbuf.st_mode) 
        || access(zLine,R_OK) ){
          NotFound(__LINE__);
        }
      }
      zRealScript = StrDup(&zLine[1]);
      if( zScript[i]==0 ){
        /* If the requested URL does not end with "/" but we had to
        ** append "index.html", then a redirect is necessary.  Otherwise
        ** none of the relative URLs in the delivered document will be
        ** correct. */
        Redirect(zRealScript, 1);
        return;
      }
      break;
    }
    zLine[i+1] = zScript[i];
    i++;
  }
  zFile = StrDup(zLine);
  zPathInfo = StrDup(&zScript[i]);
  lenFile = strlen(zFile);
  zDir = StrDup(zFile);
  for(i=strlen(zDir)-1; i>0 && zDir[i]!='/'; i--){};
  if( i==0 ){
     strcpy(zDir,"/");
  }else{
     zDir[i] = 0;
  }

  /* Check to see if there is an authorization file.  If there is,
  ** process it.
  */
  sprintf(zLine, "%s/-auth", zDir);
  if( access(zLine,R_OK)==0 && !CheckBasicAuthorization(zLine) ) return;

  /* Take appropriate action
  */
  if( (statbuf.st_mode & 0100)==0100 && access(zFile,X_OK)==0 ){
    /*
    ** The followings static variables are used to setup the environment
    ** for the CGI script
    */
    static char *default_path = "/bin:/usr/bin";
    static char *gateway_interface = "CGI/1.0";
    static struct {
      char *zEnvName;
      char **pzEnvValue;
    } cgienv[] = {
      { "AUTH_TYPE",                   &zAuthType },
      { "AUTH_CONTENT",                &zAuthArg },
      { "CONTENT_LENGTH",              &zContentLength },
      { "CONTENT_TYPE",                &zContentType },
      { "DOCUMENT_ROOT",               &zHome },
      { "GATEWAY_INTERFACE",           &gateway_interface },
      { "HTTP_ACCEPT",                 &zAccept },
      { "HTTP_COOKIE",                 &zCookie },
      { "HTTP_HOST",                   &zHttpHost },
      { "HTTP_REFERER",                &zReferer },
      { "HTTP_USER_AGENT",             &zAgent },
      { "PATH",                        &default_path },
      { "PATH_INFO",                   &zPathInfo },
      { "QUERY_STRING",                &zQueryString },
      { "REMOTE_ADDR",                 &zRemoteAddr },
      { "REQUEST_METHOD",              &zMethod },
      { "REQUEST_URI",                 &zScript },
      { "REMOTE_USER",                 &zRemoteUser },
      { "SCRIPT_DIRECTORY",            &zDir },
      { "SCRIPT_FILENAME",             &zFile },
      { "SCRIPT_NAME",                 &zRealScript },
      { "SERVER_NAME",                 &zServerName },
      { "SERVER_PORT",                 &zServerPort },
      { "SERVER_PROTOCOL",             &zProtocol },
    };
    char *zBaseFilename;   /* Filename without directory prefix */

    /* If its executable, it must be a CGI program.  Start by
    ** changing directories to the directory holding the program.
    */
    if( chdir(zDir) ){
      char zBuf[1000];
      Malfunction(__LINE__, "cannot chdir to [%s] from [%s]", 
           zDir, getcwd(zBuf,999));
    }

    /* Setup the environment appropriately.
    */
    for(i=0; i<(int)(sizeof(cgienv)/sizeof(cgienv[0])); i++){
      if( *cgienv[i].pzEnvValue ){
        SetEnv(cgienv[i].zEnvName,*cgienv[i].pzEnvValue);
      }
    }
    if( useHttps ){
      putenv("HTTPS=on");
    }

    /*
    ** Abort with an error if the CGI script is writable by anyone other
    ** than its owner.
    */
    if( statbuf.st_mode & 0022 ){
      CgiScriptWritable();
    }

    /* For the POST method all input has been written to a temporary file,
    ** so we have to redirect input to the CGI script from that file.
    */
    if( zMethod[0]=='P' ){
      dup(0);
      close(0);
      open(zTmpNam, O_RDONLY);
    }

    for(i=strlen(zFile)-1; i>=0 && zFile[i]!='/'; i--){}
    zBaseFilename = &zFile[i+1];
    if( i>=0 && strncmp(zBaseFilename,"nph-",4)==0 ){
      /* If the name of the CGI script begins with "nph-" then we are
      ** dealing with a "non-parsed headers" CGI script.  Just exec()
      ** it directly and let it handle all its own header generation.
      */
      execl(zBaseFilename,zBaseFilename,(char*)0);
      /* NOTE: No log entry written for nph- scripts */
      exit(0);
    }

    /* Fall thru to here only if this process (the server) is going
    ** to read and augment the header sent back by the CGI process.
    ** Open a pipe to receive the output from the CGI process.  Then
    ** fork the CGI process.  Once everything is done, we should be
    ** able to read the output of CGI on the "in" stream.
    */
    {
      int px[2];
      pipe(px);
      if( fork()==0 ){
        close(px[0]);
        close(1);
        dup(px[1]);
        close(px[1]);
        execl(zBaseFilename, zBaseFilename, (char*)0);
        exit(0);
      }
      close(px[1]);
      in = fdopen(px[0], "r");
    }
    if( in==0 ){
      CgiError();
    }

    /* Read and process the first line of the header returned by the
    ** CGI script.
    */
    if( useTimeout ) alarm(15);
    while( fgets(zLine,sizeof(zLine),in) ){
      if( strncmp(zLine,"Location:",9)==0 ){
        int i;
        RemoveNewline(zLine);
        z = &zLine[10];
        while( isspace(*z) ){ z++; }
        for(i=0; z[i]; i++){
          if( z[i]=='?' ){
            zQuerySuffix = StrDup("");
          }
        }
        
        if( z[0]=='/' && z[1]=='/' ){
          /* The scheme is missing.  Add it in before redirecting */
          StartResponse("302 Redirect");
          nOut += printf("Location: %s:%s%s\r\n",zHttp,z,zQuerySuffix);
          break; /* DK */
          MakeLogEntry(0);
          return;
        }else if( z[0]=='/' ){
          /* The scheme and network location are missing but we have
          ** an absolute path. */
          Redirect(z, 0); /* DK */
          break;
        }
        /* Check to see if there is a scheme prefix */
        for(i=0; z[i] && z[i]!=':' && z[i]!='/'; i++){}
        if( z[i]==':' ){
          /* We have a scheme.  Assume there is an absolute URL */
          StartResponse("302 Redirect");
          nOut += printf("Location: %s%s\r\n",z,zQuerySuffix);
          break; /* DK */
          MakeLogEntry(0);
          return;
        }
        /* Must be a relative pathname.  Construct the absolute pathname
        ** and redirect to it. */
        i = strlen(zRealScript);
        while( i>0 && zRealScript[i-1]!='/' ){ i--; }
        while( i>0 && zRealScript[i-1]=='/' ){ i--; }
        while( *z=='.' ){
          if( z[1]=='/' ){
            z += 2;
          }else if( z[1]=='.' && z[2]=='/' ){
            while( i>0 && zRealScript[i-1]!='/' ){ i--; }
            while( i>0 && zRealScript[i-1]=='/' ){ i--; }
            z += 3;
          }else{
            break;
          }
        }
        StartResponse("302 Redirect");
        nOut += printf("Location: %s://%s",zHttp,zServerName);
        if( strcmp(zServerPort,"80") ){
          nOut += printf(":%s",zServerPort);
        }
        nOut += printf("%.*s/%s%s\r\n\r\n",i,zRealScript,z,zQuerySuffix);
        MakeLogEntry(0);
        return;
      }else if( strncmp(zLine,"Status:",7)==0 ){
        int i;
        for(i=7; isspace(zLine[i]); i++){}
        nOut += printf("%s %s", zProtocol, &zLine[i]);
        strncpy(zReplyStatus, &zLine[i], 3);
        zReplyStatus[3] = 0;
        statusSent = 1;
        break;
      }else{
        int i;
        StartResponse("200 OK");
        nOut += printf("%s",zLine);
        for(i=0; zLine[i] && !isspace(zLine[i]) && zLine[i]!=':'; i++){}
        if( i<2 || zLine[i]!=':' ) break;
      }
    }

    /* Copy everything else thru without change or analysis.
    */
    if( useTimeout ) alarm(60*5);
    while( (c = getc(in))!=EOF ){
      putc(c,stdout);
      nOut++;
    }
    fclose(in);
  }else if( countSlashes(zRealScript)!=countSlashes(zScript) ){
    /* If the request URI for static content contains material past the
    ** actual content file name, report that as a 404 error. */
    NotFound(__LINE__);
  }else{
    /* If it isn't executable then it
    ** must a simple file that needs to be copied to output.
    */
    const char *zContentType = GetMimeType(zFile, lenFile);

    if( zTmpNam ) unlink(zTmpNam);
    in = fopen(zFile,"r");
    if( in==0 ) NotFound(__LINE__);
    StartResponse("200 OK");
    nOut += DateTag("Last-Modified", statbuf.st_mtime);
    nOut += printf("Content-type: %s\r\n",zContentType);
    nOut += printf("Content-length: %d\r\n\r\n",(int)statbuf.st_size);
    fflush(stdout);
    if( strcmp(zMethod,"HEAD")==0 ){
      MakeLogEntry(0);
      fclose(in);
      return;
    }
    if( useTimeout ) alarm(30 + statbuf.st_size/1000);
#ifdef linux
    {
      off_t offset = 0;
      nOut += sendfile(fileno(stdout), fileno(in), &offset, statbuf.st_size);
    }
#else
    while( (c = getc(in))!=EOF ){
      putc(c,stdout);
      nOut++;
    }
#endif
    fclose(in);
  }
  fflush(stdout);
  MakeLogEntry(0);

  /* The next request must arrive within 30 seconds or we close the connection
  */
  omitLog = 1;
  if( useTimeout ) alarm(30);
}

#define MAX_PARALLEL 50  /* Number of simultaneous children */

/*
** All possible forms of an IP address.  Needed to work around GCC strict
** aliasing rules.
*/
typedef union {
  struct sockaddr sa;              /* Abstract superclass */
  struct sockaddr_in sa4;          /* IPv4 */
  struct sockaddr_in6 sa6;         /* IPv6 */
  struct sockaddr_storage sas;     /* Should be the maximum of the above 3 */
} address;

/*
** Implement an HTTP server daemon listening on port iPort.
**
** As new connections arrive, fork a child and let child return
** out of this procedure call.  The child will handle the request.
** The parent never returns from this procedure.
**
** Return 0 to each child as it runs.  If unable to establish a
** listening socket, return non-zero.
*/
int http_server(const char *zPort, int localOnly){
  int listener[20];            /* The server sockets */
  int connection;              /* A socket for each individual connection */
  fd_set readfds;              /* Set of file descriptors for select() */
  address inaddr;              /* Remote address */
  socklen_t lenaddr;           /* Length of the inaddr structure */
  int child;                   /* PID of the child process */
  int nchildren = 0;           /* Number of child processes */
  struct timeval delay;        /* How long to wait inside select() */
  int opt = 1;                 /* setsockopt flag */
  struct addrinfo sHints;      /* Address hints */
  struct addrinfo *pAddrs, *p; /* */
  int rc;                      /* Result code */
  int i, n;
  int maxFd = -1;
  
  memset(&sHints, 0, sizeof(sHints));
  if( ipv4Only ){
    sHints.ai_family = PF_INET;
    /*printf("ipv4 only\n");*/
  }else if( ipv6Only ){
    sHints.ai_family = PF_INET6;
    /*printf("ipv6 only\n");*/
  }else{
    sHints.ai_family = PF_UNSPEC;
  }
  sHints.ai_socktype = SOCK_STREAM;
  sHints.ai_flags = AI_PASSIVE;
  sHints.ai_protocol = 0;
  rc = getaddrinfo(localOnly ? "localhost": 0, zPort, &sHints, &pAddrs);
  if( rc ){
    fprintf(stderr, "could not get addr info: %s", 
            rc!=EAI_SYSTEM ? gai_strerror(rc) : strerror(errno));
    return 1;
  }
  for(n=0, p=pAddrs; n<(int)(sizeof(listener)/sizeof(listener[0])) && p!=0;
        p=p->ai_next){
    listener[n] = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if( listener[n]>=0 ){
      /* if we can't terminate nicely, at least allow the socket to be reused */
      setsockopt(listener[n], SOL_SOCKET, SO_REUSEADDR,&opt, sizeof(opt));
      
#if defined(IPV6_V6ONLY)
      if( p->ai_family==AF_INET6 ){
        int v6only = 1;
        setsockopt(listener[n], IPPROTO_IPV6, IPV6_V6ONLY,
                    &v6only, sizeof(v6only));
      }
#endif
      
      if( bind(listener[n], p->ai_addr, p->ai_addrlen)<0 ){
        printf("bind failed: %s\n", strerror(errno));
        close(listener[n]);
        continue;
      }
      if( listen(listener[n], 20)<0 ){
        printf("listen() failed: %s\n", strerror(errno));
        close(listener[n]);
        continue;
      }
      n++;
    }
  }
  if( n==0 ){
    fprintf(stderr, "cannot open any sockets\n");
    return 1;
  }

  while( 1 ){
    if( nchildren>MAX_PARALLEL ){
      /* Slow down if connections are arriving too fast */
      sleep( nchildren-MAX_PARALLEL );
    }
    delay.tv_sec = 60;
    delay.tv_usec = 0;
    FD_ZERO(&readfds);
    for(i=0; i<n; i++){
      assert( listener[i]>=0 );
      FD_SET( listener[i], &readfds);
      if( listener[i]>maxFd ) maxFd = listener[i];
    }
    select( maxFd+1, &readfds, 0, 0, &delay);
    for(i=0; i<n; i++){
      if( FD_ISSET(listener[i], &readfds) ){
        lenaddr = sizeof(inaddr);
        connection = accept(listener[i], &inaddr.sa, &lenaddr);
        if( connection>=0 ){
          child = fork();
          if( child!=0 ){
            if( child>0 ) nchildren++;
            close(connection);
            /* printf("subprocess %d started...\n", child); fflush(stdout); */
          }else{
            int nErr = 0, fd;
            close(0);
            fd = dup(connection);
            if( fd!=0 ) nErr++;
            close(1);
            fd = dup(connection);
            if( fd!=1 ) nErr++;
            close(connection);
            return nErr;
          }
        }
      }
      /* Bury dead children */
      while( (child = waitpid(0, 0, WNOHANG))>0 ){
        /* printf("process %d ends\n", child); fflush(stdout); */
        nchildren--;
      }
    }
  }
  /* NOT REACHED */  
  exit(1);
}


int main(int argc, char **argv){
  int i;                    /* Loop counter */
  char *zPermUser = 0;      /* Run daemon with this user's permissions */
  const char *zPort = 0;    /* Implement an HTTP server process */
  int useChrootJail = 1;    /* True to use a change-root jail */
  struct passwd *pwd = 0;   /* Information about the user */

  /* Record the time when processing begins.
  */
  gettimeofday(&beginTime, 0);

  /* Parse command-line arguments
  */
  while( argc>1 && argv[1][0]=='-' ){
    char *z = argv[1];
    char *zArg = argc>=3 ? argv[2] : "0";
    if( z[0]=='-' && z[1]=='-' ) z++;
    if( strcmp(z,"-user")==0 ){
      zPermUser = zArg;
    }else if( strcmp(z,"-root")==0 ){
      zRoot = zArg;
    }else if( strcmp(z,"-logfile")==0 ){
      zLogFile = zArg;
    }else if( strcmp(z,"-https")==0 ){
      useHttps = atoi(zArg);
      zHttp = useHttps ? "http" : "https";
    }else if( strcmp(z, "-port")==0 ){
      zPort = zArg;
      standalone = 1;
    }else if( strcmp(z, "-family")==0 ){
      if( strcmp(zArg, "ipv4")==0 ){
        ipv4Only = 1;
      }else if( strcmp(zArg, "ipv6")==0 ){
        ipv6Only = 1;
      }else{
        Malfunction(__LINE__, "unknown IP protocol: [%s]", zArg);
      }
    }else if( strcmp(z, "-jail")==0 ){
      if( atoi(zArg)==0 ){
        useChrootJail = 0;
      }
    }else if( strcmp(z, "-debug")==0 ){
      if( atoi(zArg) ){
        useTimeout = 0;
      }
    }else{
      Malfunction(__LINE__, "unknown argument: [%s]", z);
    }
    argv += 2;
    argc -= 2;
  }
  if( zRoot==0 ){
    if( standalone ){
      zRoot = ".";
    }else{
      Malfunction(__LINE__, "no --root specified");
    }
  }
  
  /* Change directories to the root of the HTTP filesystem.  Then
  ** create a chroot jail there.
  */
  if( chdir(zRoot)!=0 ){
    Malfunction(__LINE__, "cannot change to directory [%s]", zRoot);
  }

  /* Get information about the user if available */
  if( zPermUser ) pwd = getpwnam(zPermUser);

  /* Enter the chroot jail if requested */  
  if( zPermUser && useChrootJail && getuid()==0 ){
    if( chroot(".")<0 ){
      Malfunction(__LINE__, "unable to create chroot jail");
    }else{
      zRoot = "";
    }
  }

  /* Activate the server, if requested */
  if( zPort && http_server(zPort, 0) ){
    Malfunction(__LINE__, "failed to start server");
  }

  /* Drop root privileges.
  */
  if( zPermUser ){
    if( pwd ){
      setgid(pwd->pw_gid);
      setuid(pwd->pw_uid);
    }else{
      Malfunction(__LINE__, "no such user [%s]", zPermUser);
    }
  }
  if( getuid()==0 ){
    Malfunction(__LINE__, "cannot run as root");
  }

  /* Get the IP address from when the request originates
  */
  {
    address remoteAddr;
    unsigned int size = sizeof(remoteAddr);
    char zHost[NI_MAXHOST];
    if( getpeername(0, &remoteAddr.sa, &size)>=0 ){
      getnameinfo(&remoteAddr.sa, size, zHost, sizeof(zHost), 0, 0,
                  NI_NUMERICHOST);
      zRemoteAddr = StrDup(zHost);
    }
  }

  /* Process the input stream */
  for(i=0; i<100; i++){
    ProcessOneRequest(0);
  }
  ProcessOneRequest(1);
  exit(0);
}

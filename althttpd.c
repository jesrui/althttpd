/*
** 2001-09-15
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
**
** This source code file implements a small, simple, stand-alone HTTP
** server.  
**
** Features:
**
**     * Launched from inetd/xinetd/stunnel4, or as a stand-alone server
**     * One process per request
**     * Deliver static content or run CGI or SCGI
**     * Virtual sites based on the "Host:" property of the HTTP header
**     * Runs in a chroot jail
**     * Unified log file in a CSV format
**     * Small code base (this 1 file) to facilitate security auditing
**     * Simple setup - no configuration files to misconfigure
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
**        It will automatically chroot to /home/www and become user "nobody".
**        The logfile name should be relative to the chroot jail.
**
**    (2) Directories of the form "*.website" (ex: www_sqlite_org.website)
**        contain content.  The directory is chosen based on the HTTP_HOST
**        request header.  If there is no HTTP_HOST header or if the
**        corresponding host directory does not exist, then the
**        "default.website" is used.  If the HTTP_HOST header contains any
**        charaters other than [a-zA-Z0-9_.,*~/] then a 403 error is
**        generated.
**
**    (3) Any file or directory whose name begins with "." or "-" is ignored,
**        except if the URL begins with "/.well-known/" then initial "." and
**        "-" characters are allowed, but not initial "..".  The exception is
**        for RFC-5785 to allow letsencrypt or certbot to generate a TLS cert
**        using webroot.
**
**    (4) Characters other than [0-9a-zA-Z,-./:_~] and any %HH characters
**        escapes in the filename are all translated into "_".  This is
**        a defense against cross-site scripting attacks and other mischief.
**
**    (5) Executable files are run as CGI.  Files whose name ends with ".scgi"
**        trigger and SCGI request (see item 10 below).  All other files
**        are delivered as is.
**
**    (6) For SSL support use stunnel and add the -https 1 option on the
**        httpd command-line.
**
**    (7) If a file named "-auth" exists in the same directory as the file to
**        be run as CGI or to be delivered, then it contains information
**        for HTTP Basic authorization.  See file format details below.
**
**    (8) To run as a stand-alone server, simply add the "-port N" command-line
**        option to define which TCP port to listen on.
**
**    (9) For static content, the mimetype is determined by the file suffix
**        using a table built into the source code below.  If you have
**        unusual content files, you might need to extend this table.
**
**   (10) Content files that end with ".scgi" and that contain text of the
**        form "SCGI hostname port" will format an SCGI request and send it
**        to hostname:port, the relay back the reply.  Error behavior is
**        determined by subsequent lines of the .scgi file.  See SCGI below
**        for details.
**
** Command-line Options:
**
**  --root DIR       Defines the directory that contains the various
**                   $HOST.website subdirectories, each containing web content 
**                   for a single virtual host.  If launched as root and if
**                   "--user USER" also appears on the command-line and if
**                   "--jail 0" is omitted, then the process runs in a chroot
**                   jail rooted at this directory and under the userid USER.
**                   This option is required for xinetd launch but defaults
**                   to "." for a stand-alone web server.
**
**  --port N         Run in standalone mode listening on TCP port N
**
**  --user USER      Define the user under which the process should run if
**                   originally launched as root.  This process will refuse to
**                   run as root (for security).  If this option is omitted and
**                   the process is launched as root, it will abort without
**                   processing any HTTP requests.
**
**  --logfile FILE   Append a single-line, CSV-format, log file entry to FILE
**                   for each HTTP request.  FILE should be a full pathname.
**                   The FILE name is interpreted inside the chroot jail.  The
**                   FILE name is expanded using strftime() if it contains
**                   at least one '%' and is not too long.
**
**  --https          Indicates that input is coming over SSL and is being
**                   decoded upstream, perhaps by stunnel.  (This program
**                   only understands plaintext.)
**
**  --family ipv4    Only accept input from IPV4 or IPV6, respectively.
**  --family ipv6    These options are only meaningful if althttpd is run
**                   as a stand-alone server.
**
**  --jail BOOLEAN   Indicates whether or not to form a chroot jail if 
**                   initially run as root.  The default is true, so the only
**                   useful variant of this option is "--jail 0" which prevents
**                   the formation of the chroot jail.
**
**  --max-age SEC    The value for "Cache-Control: max-age=%d".  Defaults to
**                   120 seconds.
**
**  --max-cpu SEC    Maximum number of seconds of CPU time allowed per
**                   HTTP connection.  Default 30.  0 means no limit.
**
**  --debug          Disables input timeouts.  This is useful for debugging
**                   when inputs is being typed in manually.
**
** Command-line options can take either one or two initial "-" characters.
** So "--debug" and "-debug" mean the same thing, for example.
**
**
** Security Features:
**
** (1)  This program automatically puts itself inside a chroot jail if
**      it can and if not specifically prohibited by the "--jail 0"
**      command-line option.  The root of the jail is the directory that
**      contains the various $HOST.website content subdirectories.
**
** (2)  No input is read while this process has root privileges.  Root
**      privileges are dropped prior to reading any input (but after entering
**      the chroot jail, of course).  If root privileges cannot be dropped
**      (for example because the --user command-line option was omitted or
**      because the user specified by the --user option does not exist), 
**      then the process aborts with an error prior to reading any input.
**
** (3)  The length of an HTTP request is limited to MAX_CONTENT_LENGTH bytes
**      (default: 250 million).  Any HTTP request longer than this fails
**      with an error.
**
** (4)  There are hard-coded time-outs on each HTTP request.  If this process
**      waits longer than the timeout for the complete request, or for CGI
**      to finish running, then this process aborts.  (The timeout feature
**      can be disabled using the --debug command-line option.)
**
** (5)  If the HTTP_HOST request header contains characters other than
**      [0-9a-zA-Z,-./:_~] then the entire request is rejected.
**
** (6)  Any characters in the URI pathname other than [0-9a-zA-Z,-./:_~]
**      are converted into "_".  This applies to the pathname only, not
**      to the query parameters or fragment.
**
** (7)  If the first character of any URI pathname component is "." or "-"
**      then a 404 Not Found reply is generated.  This prevents attacks
**      such as including ".." or "." directory elements in the pathname
**      and allows placing files and directories in the content subdirectory
**      that are invisible to all HTTP requests, by making the first 
**      character of the file or subdirectory name "-" or ".".
**
** (8)  The request URI must begin with "/" or else a 404 error is generated.
**
** (9)  This program never sets the value of an environment variable to a
**      string that begins with "() {".
**
** Security Auditing:
**
** This webserver mostly only serves static content.  Any security risk will
** come from CGI and SCGI.  To check an installation for security, then, it
** makes sense to focus on the CGI and SCGI scripts.
**
** To local all CGI files:
**
**          find *.website -executable -type f -print
**     OR:  find *.website -perm +0111 -type f -print
**
** The first form of the "find" command is preferred, but is only supported
** by GNU find.  On a Mac, you'll have to use the second form.
**
** To find all SCGI files:
**
**          find *.website -name '*.scgi' -type f -print
**
** If any file is a security concern, it can be disabled on a live
** installation by turning off read permissions:
**
**          chmod 0000 file-of-concern
**
** SCGI Specification Files:
**
** Content files (files without the execute bit set) that end with ".scgi"
** specify a connection to an SCGI server.  The format of the .scgi file
** follows this template:
**
**      SCGI hostname port
**      fallback: fallback-filename
**      relight: relight-command
**
** The first line specifies the location and TCP/IP port of the SCGI server
** that will handle the request.  Subsequent lines determine what to do if
** the SCGI server cannot be contacted.  If the "relight:" line is present,
** then the relight-command is run using system() and the connection is
** retried after a 1-second delay.  Use "&" at the end of the relight-command
** to run it in the background.  Make sure the relight-command does not
** send generate output, or that output will become part of the SCGI reply.
** Add a ">/dev/null" suffix (before the "&") to the relight-command if
** necessary to suppress output.  If there is no relight-command, or if the
** relight is attempted but the SCGI server still cannot be contacted, then
** the content of the fallback-filename file is returned as a substitute for
** the SCGI request.  The mimetype is determined by the suffix on the
** fallback-filename.  The fallback-filename would typically be an error
** message indicating that the service is temporarily unavailable.
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
**
** Because of security rule (7), there is no way for the content of the "-auth"
** file to leak out via HTTP request.
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
#include <sys/resource.h>
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
#include <signal.h>
#ifdef linux
#include <sys/sendfile.h>
#endif
#include <assert.h>

/*
** Configure the server by setting the following macros and recompiling.
*/
#ifndef DEFAULT_PORT
#define DEFAULT_PORT "80"             /* Default TCP port for HTTP */
#endif
#ifndef MAX_CONTENT_LENGTH
#define MAX_CONTENT_LENGTH 250000000  /* Max length of HTTP request content */
#endif
#ifndef MAX_CPU
#define MAX_CPU 30                /* Max CPU cycles in seconds */
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
static char *zAcceptEncoding =0; /* gzip or default */
static char *zContentLength = 0; /* Content length reported in the header */
static char *zContentType = 0;   /* Content type reported in the header */
static char *zQuerySuffix = 0;   /* The part of the URL after the first ? */
static char *zAuthType = 0;      /* Authorization type (basic or digest) */
static char *zAuthArg = 0;       /* Authorization values */
static char *zRemoteUser = 0;    /* REMOTE_USER set by authorization module */
static char *zIfNoneMatch= 0;    /* The If-None-Match header value */
static char *zIfModifiedSince=0; /* The If-Modified-Since header value */
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
static int mxAge = 120;          /* Cache-control max-age */
static char *default_path = "/bin:/usr/bin";  /* Default PATH variable */
static char *zScgi = 0;          /* Value of the SCGI env variable */
static int rangeStart = 0;       /* Start of a Range: request */
static int rangeEnd = 0;         /* End of a Range: request */
static int maxCpu = MAX_CPU;     /* Maximum CPU time per process */

/*
** Mapping between CGI variable names and values stored in
** global variables.
*/
static struct {
  char *zEnvName;
  char **pzEnvValue;
} cgienv[] = {
  { "CONTENT_LENGTH",          &zContentLength }, /* Must be first for SCGI */
  { "AUTH_TYPE",                   &zAuthType },
  { "AUTH_CONTENT",                &zAuthArg },
  { "CONTENT_TYPE",                &zContentType },
  { "DOCUMENT_ROOT",               &zHome },
  { "HTTP_ACCEPT",                 &zAccept },
  { "HTTP_ACCEPT_ENCODING",        &zAcceptEncoding },
  { "HTTP_COOKIE",                 &zCookie },
  { "HTTP_HOST",                   &zHttpHost },
  { "HTTP_IF_MODIFIED_SINCE",      &zIfModifiedSince },
  { "HTTP_IF_NONE_MATCH",          &zIfNoneMatch },
  { "HTTP_REFERER",                &zReferer },
  { "HTTP_USER_AGENT",             &zAgent },
  { "PATH",                        &default_path },
  { "PATH_INFO",                   &zPathInfo },
  { "QUERY_STRING",                &zQueryString },
  { "REMOTE_ADDR",                 &zRemoteAddr },
  { "REQUEST_METHOD",              &zMethod },
  { "REQUEST_URI",                 &zScript },
  { "REMOTE_USER",                 &zRemoteUser },
  { "SCGI",                        &zScgi },
  { "SCRIPT_DIRECTORY",            &zDir },
  { "SCRIPT_FILENAME",             &zFile },
  { "SCRIPT_NAME",                 &zRealScript },
  { "SERVER_NAME",                 &zServerName },
  { "SERVER_PORT",                 &zServerPort },
  { "SERVER_PROTOCOL",             &zProtocol },
};


/*
** Double any double-quote characters in a string.
*/
static char *Escape(char *z){
  size_t i, j;
  size_t n;
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
** Convert a struct timeval into an integer number of microseconds
*/
static long long int tvms(struct timeval *p){
  return ((long long int)p->tv_sec)*1000000 + (long long int)p->tv_usec;
}

/*
** Make an entry in the log file.  If the HTTP connection should be
** closed, then terminate this process.  Otherwise return.
*/
static void MakeLogEntry(int exitCode, int lineNum){
  FILE *log;
  if( zTmpNam ){
    unlink(zTmpNam);
  }
  if( zLogFile && !omitLog ){
    struct timeval now;
    struct tm *pTm;
    struct rusage self, children;
    int waitStatus;
    char *zRM = zRemoteUser ? zRemoteUser : "";
    char *zFilename;
    size_t sz;
    char zDate[200];
    char zExpLogFile[500];

    if( zScript==0 ) zScript = "";
    if( zRealScript==0 ) zRealScript = "";
    if( zRemoteAddr==0 ) zRemoteAddr = "";
    if( zHttpHost==0 ) zHttpHost = "";
    if( zReferer==0 ) zReferer = "";
    if( zAgent==0 ) zAgent = "";
    gettimeofday(&now, 0);
    pTm = localtime(&now.tv_sec);
    strftime(zDate, sizeof(zDate), "%Y-%m-%d %H:%M:%S", pTm);
    sz = strftime(zExpLogFile, sizeof(zExpLogFile), zLogFile, pTm);
    if( sz>0 && sz<sizeof(zExpLogFile)-2 ){
      zFilename = zExpLogFile;
    }else{
      zFilename = zLogFile;
    }
    waitpid(-1, &waitStatus, WNOHANG);
    getrusage(RUSAGE_SELF, &self);
    getrusage(RUSAGE_CHILDREN, &children);
    if( (log = fopen(zFilename,"a"))!=0 ){
#ifdef COMBINED_LOG_FORMAT
      strftime(zDate, sizeof(zDate), "%d/%b/%Y:%H:%M:%S %Z", pTm);
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
      ** (17) Line number in source file
      */
      fprintf(log,
        "%s,%s,\"%s://%s%s\",\"%s\","
           "%s,%d,%d,%lld,%lld,%lld,%lld,%lld,%d,\"%s\",\"%s\",%d,%d\n",
        zDate, zRemoteAddr, zHttp, Escape(zHttpHost), Escape(zScript),
        Escape(zReferer), zReplyStatus, nIn, nOut,
        tvms(&self.ru_utime) - tvms(&priorSelf.ru_utime),
        tvms(&self.ru_stime) - tvms(&priorSelf.ru_stime),
        tvms(&children.ru_utime) - tvms(&priorChild.ru_utime),
        tvms(&children.ru_stime) - tvms(&priorChild.ru_stime),
        tvms(&now) - tvms(&beginTime),
        nRequest, Escape(zAgent), Escape(zRM),
        (int)(strlen(zHttp)+strlen(zHttpHost)+strlen(zRealScript)+3),
        lineNum
      );
      priorSelf = self;
      priorChild = children;
#endif
      fclose(log);
      nIn = nOut = 0;
    }
  }
  if( closeConnection ){
    exit(exitCode);
  }
  statusSent = 0;
}

/*
** Allocate memory safely
*/
static char *SafeMalloc( size_t size ){
  char *p;

  p = (char*)malloc(size);
  if( p==0 ){
    strcpy(zReplyStatus, "998");
    MakeLogEntry(1,100);  /* LOG: Malloc() failed */
    exit(1);
  }
  return p;
}

/*
** Set the value of environment variable zVar to zValue.
*/
static void SetEnv(const char *zVar, const char *zValue){
  char *z;
  size_t len;
  if( zValue==0 ) zValue="";
  /* Disable an attempted bashdoor attack */
  if( strncmp(zValue,"() {",4)==0 ) zValue = "";
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
  while( isspace(*(unsigned char*)zInput) ){ zInput++; }
  zResult = zInput;
  while( *zInput && !isspace(*(unsigned char*)zInput) ){ zInput++; }
  if( *zInput ){
    *zInput = 0;
    zInput++;
    while( isspace(*(unsigned char*)zInput) ){ zInput++; }
  }
  if( zLeftOver ){ *zLeftOver = zInput; }
  return zResult;
}

/*
** Make a copy of a string into memory obtained from malloc.
*/
static char *StrDup(const char *zSrc){
  char *zDest;
  size_t size;

  if( zSrc==0 ) return 0;
  size = strlen(zSrc) + 1;
  zDest = (char*)SafeMalloc( size );
  strcpy(zDest,zSrc);
  return zDest;
}
static char *StrAppend(char *zPrior, const char *zSep, const char *zSrc){
  char *zDest;
  size_t size;
  size_t n0, n1, n2;

  if( zSrc==0 ) return 0;
  if( zPrior==0 ) return StrDup(zSrc);
  n0 = strlen(zPrior);
  n1 = strlen(zSep);
  n2 = strlen(zSrc);
  size = n0+n1+n2+1;
  zDest = (char*)SafeMalloc( size );
  memcpy(zDest, zPrior, n0);
  free(zPrior);
  memcpy(&zDest[n0],zSep,n1);
  memcpy(&zDest[n0+n1],zSrc,n2+1);
  return zDest;
}

/*
** Compare two ETag values. Return 0 if they match and non-zero if they differ.
**
** The one on the left might be a NULL pointer and it might be quoted.
*/
static int CompareEtags(const char *zA, const char *zB){
  if( zA==0 ) return 1;
  if( zA[0]=='"' ){
    int lenB = (int)strlen(zB);
    if( strncmp(zA+1, zB, lenB)==0 && zA[lenB+1]=='"' ) return 0;
  }
  return strcmp(zA, zB);
}

/*
** Break a line at the first \n or \r character seen.
*/
static void RemoveNewline(char *z){
  if( z==0 ) return;
  while( *z && *z!='\n' && *z!='\r' ){ z++; }
  *z = 0;
}

/* Render seconds since 1970 as an RFC822 date string.  Return
** a pointer to that string in a static buffer.
*/
static char *Rfc822Date(time_t t){
  struct tm *tm;
  static char zDate[100];
  tm = gmtime(&t);
  strftime(zDate, sizeof(zDate), "%a, %d %b %Y %H:%M:%S %Z", tm);
  return zDate;
}

/*
** Print a date tag in the header.  The name of the tag is zTag.
** The date is determined from the unix timestamp given.
*/
static int DateTag(const char *zTag, time_t t){
  return printf("%s: %s\r\n", zTag, Rfc822Date(t));
}

/*
** Parse an RFC822-formatted timestamp as we'd expect from HTTP and return
** a Unix epoch time. <= zero is returned on failure.
*/
time_t ParseRfc822Date(const char *zDate){
  int mday, mon, year, yday, hour, min, sec;
  char zIgnore[4];
  char zMonth[4];
  static const char *const azMonths[] =
    {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  if( 7==sscanf(zDate, "%3[A-Za-z], %d %3[A-Za-z] %d %d:%d:%d", zIgnore,
                       &mday, zMonth, &year, &hour, &min, &sec)){
    if( year > 1900 ) year -= 1900;
    for(mon=0; mon<12; mon++){
      if( !strncmp( azMonths[mon], zMonth, 3 )){
        int nDay;
        int isLeapYr;
        static int priorDays[] =
         {  0, 31, 59, 90,120,151,181,212,243,273,304,334 };
        isLeapYr = year%4==0 && (year%100!=0 || (year+300)%400==0);
        yday = priorDays[mon] + mday - 1;
        if( isLeapYr && mon>1 ) yday++;
        nDay = (year-70)*365 + (year-69)/4 - year/100 + (year+300)/400 + yday;
        return ((time_t)(nDay*24 + hour)*60 + min)*60 + sec;
      }
    }
  }
  return 0;
}

/*
** Test procedure for ParseRfc822Date
*/
void TestParseRfc822Date(void){
  time_t t1, t2;
  for(t1=0; t1<0x7fffffff; t1 += 127){
    t2 = ParseRfc822Date(Rfc822Date(t1));
    assert( t1==t2 );
  }
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
    "Content-type: text/html; charset=utf-8\r\n"
    "\r\n"
    "<head><title lineno=\"%d\">Not Found</title></head>\n"
    "<body><h1>Document Not Found</h1>\n"
    "The document %s is not available on this server\n"
    "</body>\n", lineno, zScript);
  MakeLogEntry(0, lineno);
  exit(0);
}

/*
** Tell the client that they are not welcomed here.
*/
static void Forbidden(int lineno){
  StartResponse("403 Forbidden");
  nOut += printf(
    "Content-type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Access denied\n"
  );
  closeConnection = 1;
  MakeLogEntry(0, lineno);
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
    "Content-type: text/html; charset=utf-8\r\n"
    "\r\n"
    "<head><title>Not Authorized</title></head>\n"
    "<body><h1>401 Not Authorized</h1>\n"
    "A login and password are required for this document\n"
    "</body>\n", zRealm);
  MakeLogEntry(0, 110);  /* LOG: Not authorized */
}

/*
** Tell the client that there is an error in the script.
*/
static void CgiError(void){
  StartResponse("500 Error");
  nOut += printf(
    "Content-type: text/html; charset=utf-8\r\n"
    "\r\n"
    "<head><title>CGI Program Error</title></head>\n"
    "<body><h1>CGI Program Error</h1>\n"
    "The CGI program %s generated an error\n"
    "</body>\n", zScript);
  MakeLogEntry(0, 120);  /* LOG: CGI Error */
  exit(0);
}

/*
** This is called if we timeout or catch some other kind of signal.
** Log an error code which is 900+iSig and then quit.
*/
static void Timeout(int iSig){
  if( !debugFlag ){
    if( zScript && zScript[0] ){
      char zBuf[10];
      zBuf[0] = '9';
      zBuf[1] = '0' + (iSig/10)%10;
      zBuf[2] = '0' + iSig%10;
      zBuf[3] = 0;
      strcpy(zReplyStatus, zBuf);
      MakeLogEntry(0, 130);  /* LOG: Timeout */
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
    "Content-type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "The CGI program %s is writable by users other than its owner.\n",
    zRealScript);
  MakeLogEntry(0, 140);  /* LOG: CGI script is writable */
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
    "Content-type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Web server malfunctioned; error number %d\n\n", linenum);
  if( zFormat ){
    nOut += vprintf(zFormat, ap);
    printf("\n");
    nOut++;
  }
  MakeLogEntry(0, linenum);
  exit(0);       
}

/*
** Do a server redirect to the document specified.  The document
** name not contain scheme or network location or the query string.
** It will be just the path.
*/
static void Redirect(const char *zPath, int iStatus, int finish, int lineno){
  switch( iStatus ){
    case 301:
      StartResponse("301 Permanent Redirect");
      break;
    case 308:
      StartResponse("308 Permanent Redirect");
      break;
    default:
      StartResponse("302 Temporary Redirect");
      break;
  }
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
    MakeLogEntry(0, lineno);
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
**    *  "anyone" bypasses authentication and allows anyone to see the
**       files.  Useful in combination with "http-redirect"
*/
static int CheckBasicAuthorization(const char *zAuthFile){
  FILE *in;
  char *zRealm = "unknown realm";
  char *zLoginPswd;
  char *zName;
  char zLine[2000];

  in = fopen(zAuthFile, "rb");
  if( in==0 ){
    NotFound(150);  /* LOG: Cannot open -auth file */
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
        NotFound(160);  /* LOG:  http request on https-only page */
        fclose(in);
        return 0;
      }
    }else if( strcmp(zFieldName,"http-redirect")==0 ){
      if( !useHttps ){
        zHttp = "https";
        Redirect(zScript, 301, 1, 170); /* LOG: -auth redirect */
        fclose(in);
        return 0;
      }
    }else if( strcmp(zFieldName,"anyone")==0 ){
      fclose(in);
      return 1;
    }else{
      NotFound(180);  /* LOG:  malformed entry in -auth file */
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
    { "svg",        3, "image/svg+xml"                     },
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
    { "vsix",       4, "application/vsix"                  },
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
** Allowed characters:  0-9a-zA-Z,-./:_~
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
/* 8x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* 9x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* Ax */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* Bx */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* Cx */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* Dx */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* Ex */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* Fx */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
};

/*
** Remove all disallowed characters in the input string z[].  Convert any
** disallowed characters into "_".
**
** Not that the three character sequence "%XX" where X is any byte is
** converted into a single "_" character.
**
** Return the number of characters converted.  An "%XX" -> "_" conversion
** counts as a single character.
*/
static int sanitizeString(char *z){
  int nChange = 0;
  while( *z ){
    if( !allowedInName[*(unsigned char*)z] ){
      if( *z=='%' && z[1]!=0 && z[2]!=0 ){
        int i;
        for(i=3; (z[i-2] = z[i])!=0; i++){}
      }
      *z = '_';
      nChange++;
    }
    z++;
  }
  return nChange;
}

/*
** Count the number of "/" characters in a string.
*/
static int countSlashes(const char *z){
  int n = 0;
  while( *z ) if( *(z++)=='/' ) n++;
  return n;
}

/*
** Transfer nXfer bytes from in to out, after first discarding
** nSkip bytes from in.  Increment the nOut global variable
** according to the number of bytes transferred.
*/
static void xferBytes(FILE *in, FILE *out, int nXfer, int nSkip){
  size_t n;
  size_t got;
  char zBuf[16384];
  while( nSkip>0 ){
    n = nSkip;
    if( n>sizeof(zBuf) ) n = sizeof(zBuf);
    got = fread(zBuf, 1, n, in);
    if( got==0 ) break;
    nSkip -= got;
  }
  while( nXfer>0 ){
    n = nXfer;
    if( n>sizeof(zBuf) ) n = sizeof(zBuf);
    got = fread(zBuf, 1, n, in);
    if( got==0 ) break;
    fwrite(zBuf, got, 1, out);
    nOut += got;
    nXfer -= got;
  }
}

/*
** Send the text of the file named by zFile as the reply.  Use the
** suffix on the end of the zFile name to determine the mimetype.
**
** Return 1 to omit making a log entry for the reply.
*/
static int SendFile(
  const char *zFile,      /* Name of the file to send */
  int lenFile,            /* Length of the zFile name in bytes */
  struct stat *pStat      /* Result of a stat() against zFile */
){
  const char *zContentType;
  time_t t;
  FILE *in;
  char zETag[100];

  zContentType = GetMimeType(zFile, lenFile);
  if( zTmpNam ) unlink(zTmpNam);
  sprintf(zETag, "m%xs%x", (int)pStat->st_mtime, (int)pStat->st_size);
  if( CompareEtags(zIfNoneMatch,zETag)==0
   || (zIfModifiedSince!=0
        && (t = ParseRfc822Date(zIfModifiedSince))>0
        && t>=pStat->st_mtime)
  ){
    StartResponse("304 Not Modified");
    nOut += DateTag("Last-Modified", pStat->st_mtime);
    nOut += printf("Cache-Control: max-age=%d\r\n", mxAge);
    nOut += printf("ETag: \"%s\"\r\n", zETag);
    nOut += printf("\r\n");
    fflush(stdout);
    MakeLogEntry(0, 470);  /* LOG: ETag Cache Hit */
    return 1;
  }
  in = fopen(zFile,"rb");
  if( in==0 ) NotFound(480); /* LOG: fopen() failed for static content */
  if( rangeEnd>0 && rangeStart<pStat->st_size ){
    StartResponse("206 Partial Content");
    if( rangeEnd>=pStat->st_size ){
      rangeEnd = pStat->st_size-1;
    }
    nOut += printf("Content-Range: bytes %d-%d/%d\r\n",
                    rangeStart, rangeEnd, (int)pStat->st_size);
    pStat->st_size = rangeEnd + 1 - rangeStart;
  }else{
    StartResponse("200 OK");
    rangeStart = 0;
  }
  nOut += DateTag("Last-Modified", pStat->st_mtime);
  nOut += printf("Cache-Control: max-age=%d\r\n", mxAge);
  nOut += printf("ETag: \"%s\"\r\n", zETag);
  nOut += printf("Content-type: %s; charset=utf-8\r\n",zContentType);
  nOut += printf("Content-length: %d\r\n\r\n",(int)pStat->st_size);
  fflush(stdout);
  if( strcmp(zMethod,"HEAD")==0 ){
    MakeLogEntry(0, 2); /* LOG: Normal HEAD reply */
    fclose(in);
    fflush(stdout);
    return 1;
  }
  if( useTimeout ) alarm(30 + pStat->st_size/1000);
#ifdef linux
  {
    off_t offset = rangeStart;
    nOut += sendfile(fileno(stdout), fileno(in), &offset, pStat->st_size);
  }
#else
  xferBytes(in, stdout, (int)pStat->st_size, rangeStart);
#endif
  fclose(in);
  return 0;
}

/*
** A CGI or SCGI script has run and is sending its reply back across
** the channel "in".  Process this reply into an appropriate HTTP reply.
** Close the "in" channel when done.
*/
static void CgiHandleReply(FILE *in){
  int seenContentLength = 0;   /* True if Content-length: header seen */
  int contentLength = 0;       /* The content length */
  size_t nRes = 0;             /* Bytes of payload */
  size_t nMalloc = 0;          /* Bytes of space allocated to aRes */
  char *aRes = 0;              /* Payload */
  int c;                       /* Next character from in */
  char *z;                     /* Pointer to something inside of zLine */
  int iStatus = 0;             /* Reply status code */
  char zLine[1000];            /* One line of reply from the CGI script */

  if( useTimeout ){
    /* Disable the timeout, so that we can implement Hanging-GET or
    ** long-poll style CGIs.  The RLIMIT_CPU will serve as a safety
    ** to help prevent a run-away CGI */
    alarm(0);
  }
  while( fgets(zLine,sizeof(zLine),in) && !isspace((unsigned char)zLine[0]) ){
    if( strncasecmp(zLine,"Location:",9)==0 ){
      StartResponse("302 Redirect");
      RemoveNewline(zLine);
      z = &zLine[10];
      while( isspace(*(unsigned char*)z) ){ z++; }
      nOut += printf("Location: %s\r\n",z);
      rangeEnd = 0;
    }else if( strncasecmp(zLine,"Status:",7)==0 ){
      int i;
      for(i=7; isspace((unsigned char)zLine[i]); i++){}
      nOut += printf("%s %s", zProtocol, &zLine[i]);
      strncpy(zReplyStatus, &zLine[i], 3);
      zReplyStatus[3] = 0;
      iStatus = atoi(zReplyStatus);
      if( iStatus!=200 ) rangeEnd = 0;
      statusSent = 1;
    }else if( strncasecmp(zLine, "Content-length:", 15)==0 ){
      seenContentLength = 1;
      contentLength = atoi(zLine+15);
    }else{
      size_t nLine = strlen(zLine);
      if( nRes+nLine >= nMalloc ){
        nMalloc += nMalloc + nLine*2;
        aRes = realloc(aRes, nMalloc+1);
        if( aRes==0 ){
          Malfunction(600, "Out of memory: %d bytes", nMalloc);
        }
      }
      memcpy(aRes+nRes, zLine, nLine);
      nRes += nLine;
    }
  }

  /* Copy everything else thru without change or analysis.
  */
  if( rangeEnd>0 && seenContentLength && rangeStart<contentLength ){
    StartResponse("206 Partial Content");
    if( rangeEnd>=contentLength ){
      rangeEnd = contentLength-1;
    }
    nOut += printf("Content-Range: bytes %d-%d/%d\r\n",
                    rangeStart, rangeEnd, contentLength);
    contentLength = rangeEnd + 1 - rangeStart;
  }else{
    StartResponse("200 OK");
  }
  if( nRes>0 ){
    aRes[nRes] = 0;
    printf("%s", aRes);
    nOut += nRes;
    nRes = 0;
  }
  if( iStatus==304 ){
    nOut += printf("\r\n\r\n");
  }else if( seenContentLength ){
    nOut += printf("Content-length: %d\r\n\r\n", contentLength);
    xferBytes(in, stdout, contentLength, rangeStart);
  }else{
    while( (c = getc(in))!=EOF ){
      if( nRes>=nMalloc ){
        nMalloc = nMalloc*2 + 1000;
        aRes = realloc(aRes, nMalloc+1);
        if( aRes==0 ){
           Malfunction(610, "Out of memory: %d bytes", nMalloc);
        }
      }
      aRes[nRes++] = c;
    }
    if( nRes ){
      aRes[nRes] = 0;
      nOut += printf("Content-length: %d\r\n\r\n%s", (int)nRes, aRes);
    }else{
      nOut += printf("Content-length: 0\r\n\r\n");
    }
  }
  free(aRes);
  fclose(in);
}

/*
** Send an SCGI request to a host identified by zFile and process the
** reply.
*/
static void SendScgiRequest(const char *zFile, const char *zScript){
  FILE *in;
  FILE *s;
  char *z;
  char *zHost;
  char *zPort = 0;
  char *zRelight = 0;
  char *zFallback = 0;
  int rc;
  int iSocket = -1;
  struct addrinfo hints;
  struct addrinfo *ai = 0;
  struct addrinfo *p;
  char *zHdr;
  size_t nHdr = 0;
  size_t nHdrAlloc;
  int i;
  char zLine[1000];
  char zExtra[1000];
  in = fopen(zFile, "rb");
  if( in==0 ){
    Malfunction(700, "cannot open \"%s\"\n", zFile);
  }
  if( fgets(zLine, sizeof(zLine)-1, in)==0 ){
    Malfunction(701, "cannot read \"%s\"\n", zFile);
  }
  if( strncmp(zLine,"SCGI ",5)!=0 ){
    Malfunction(702, "misformatted SCGI spec \"%s\"\n", zFile);
  }
  z = zLine+5;
  zHost = GetFirstElement(z,&z);
  zPort = GetFirstElement(z,0);
  if( zHost==0 || zHost[0]==0 || zPort==0 || zPort[0]==0 ){
    Malfunction(703, "misformatted SCGI spec \"%s\"\n", zFile);
  }
  while( fgets(zExtra, sizeof(zExtra)-1, in) ){
    char *zCmd = GetFirstElement(zExtra,&z);
    if( zCmd==0 ) continue;
    if( zCmd[0]=='#' ) continue;
    RemoveNewline(z);
    if( strcmp(zCmd, "relight:")==0 ){
      free(zRelight);
      zRelight = StrDup(z);
      continue;
    }
    if( strcmp(zCmd, "fallback:")==0 ){
      free(zFallback);
      zFallback = StrDup(z);
      continue;
    }
    Malfunction(704, "unrecognized line in SCGI spec: \"%s %s\"\n",
                zCmd, z ? z : "");
  }
  fclose(in);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  rc = getaddrinfo(zHost,zPort,&hints,&ai);
  if( rc ){
    Malfunction(704, "cannot resolve SCGI server name %s:%s\n%s\n",
                zHost, zPort, gai_strerror(rc));
  }
  while(1){  /* Exit via break */
    for(p=ai; p; p=p->ai_next){
      iSocket = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if( iSocket<0 ) continue;
      if( connect(iSocket,p->ai_addr,p->ai_addrlen)>=0 ) break;
      close(iSocket);
    }
    if( iSocket<0 || (s = fdopen(iSocket,"r+"))==0 ){
      if( iSocket>=0 ) close(iSocket);
      if( zRelight ){
        rc = system(zRelight);
        if( rc ){
          Malfunction(721,"Relight failed with %d: \"%s\"\n",
                      rc, zRelight);
        }
        free(zRelight);
        zRelight = 0;
        sleep(1);
        continue;
      }
      if( zFallback ){
        struct stat statbuf;
        int rc;
        memset(&statbuf, 0, sizeof(statbuf));
        if( chdir(zDir) ){
          char zBuf[1000];
          Malfunction(720, /* LOG: chdir() failed */
               "cannot chdir to [%s] from [%s]", 
               zDir, getcwd(zBuf,999));
        }
        rc = stat(zFallback, &statbuf);
        if( rc==0 && S_ISREG(statbuf.st_mode) && access(zFallback,R_OK)==0 ){
          closeConnection = 1;
          rc = SendFile(zFallback, (int)strlen(zFallback), &statbuf);
          free(zFallback);
          exit(0);
        }else{
          Malfunction(706, "bad fallback file: \"%s\"\n", zFallback);
        }
      }
      Malfunction(707, "cannot open socket to SCGI server %s\n",
                  zScript);
    }
    break;
  }

  nHdrAlloc = 0;
  zHdr = 0;
  if( zContentLength==0 ) zContentLength = "0";
  zScgi = "1";
  for(i=0; i<(int)(sizeof(cgienv)/sizeof(cgienv[0])); i++){
    int n1, n2;
    if( cgienv[i].pzEnvValue[0]==0 ) continue;
    n1 = (int)strlen(cgienv[i].zEnvName);
    n2 = (int)strlen(*cgienv[i].pzEnvValue);
    if( n1+n2+2+nHdr >= nHdrAlloc ){
      nHdrAlloc = nHdr + n1 + n2 + 1000;
      zHdr = realloc(zHdr, nHdrAlloc);
      if( zHdr==0 ){
        Malfunction(706, "out of memory");
      }
    }
    memcpy(zHdr+nHdr, cgienv[i].zEnvName, n1);
    nHdr += n1;
    zHdr[nHdr++] = 0;
    memcpy(zHdr+nHdr, *cgienv[i].pzEnvValue, n2);
    nHdr += n2;
    zHdr[nHdr++] = 0;
  }
  zScgi = 0;
  fprintf(s,"%d:",(int)nHdr);
  fwrite(zHdr, 1, nHdr, s);
  fprintf(s,",");
  free(zHdr);
  if( zMethod[0]=='P'
   && atoi(zContentLength)>0 
   && (in = fopen(zTmpNam,"r"))!=0 ){
    size_t n;
    while( (n = fread(zLine,1,sizeof(zLine),in))>0 ){
      fwrite(zLine, 1, n, s);
    }
    fclose(in);
  }
  fflush(s);
  CgiHandleReply(s);
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
  int i, j, j0;
  char *z;                  /* Used to parse up a string */
  struct stat statbuf;      /* Information about the file to be retrieved */
  FILE *in;                 /* For reading from CGI scripts */
#ifdef LOG_HEADER
  FILE *hdrLog = 0;         /* Log file for complete header content */
#endif
  char zLine[1000];         /* A buffer for input lines or forming names */

  /* Change directories to the root of the HTTP filesystem
  */
  if( chdir(zRoot[0] ? zRoot : "/")!=0 ){
    char zBuf[1000];
    Malfunction(190,   /* LOG: chdir() failed */
         "cannot chdir to [%s] from [%s]",
         zRoot, getcwd(zBuf,999));
  }
  nRequest++;

  /*
  ** We must receive a complete header within 15 seconds
  */
  signal(SIGALRM, Timeout);
  signal(SIGSEGV, Timeout);
  signal(SIGPIPE, Timeout);
  signal(SIGXCPU, Timeout);
  if( useTimeout ) alarm(15);

  /* Get the first line of the request and parse out the
  ** method, the script and the protocol.
  */
  if( fgets(zLine,sizeof(zLine),stdin)==0 ){
    exit(0);
  }
  gettimeofday(&beginTime, 0);
  omitLog = 0;
  nIn += strlen(zLine);

  /* Parse the first line of the HTTP request */
  zMethod = StrDup(GetFirstElement(zLine,&z));
  zRealScript = zScript = StrDup(GetFirstElement(z,&z));
  zProtocol = StrDup(GetFirstElement(z,&z));
  if( zProtocol==0 || strncmp(zProtocol,"HTTP/",5)!=0 || strlen(zProtocol)!=8 ){
    StartResponse("400 Bad Request");
    nOut += printf(
      "Content-type: text/plain; charset=utf-8\r\n"
      "\r\n"
      "This server does not understand the requested protocol\n"
    );
    MakeLogEntry(0, 200); /* LOG: bad protocol in HTTP header */
    exit(0);
  }
  if( zScript[0]!='/' ) NotFound(210); /* LOG: Empty request URI */
  while( zScript[1]=='/' ){
    zScript++;
    zRealScript++;
  }
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
      "Content-type: text/plain; charset=utf-8\r\n"
      "\r\n"
      "The %s method is not implemented on this server.\n",
      zMethod);
    MakeLogEntry(0, 220); /* LOG: Unknown request method */
    exit(0);
  }

  /* If there is a log file (if zLogFile!=0) and if the pathname in
  ** the first line of the http request contains the magic string
  ** "FullHeaderLog" then write the complete header text into the
  ** file %s(zLogFile)-hdr.  Overwrite the file.  This is for protocol
  ** debugging only and is only enabled if althttpd is compiled with
  ** the -DLOG_HEADER=1 option.
  */
#ifdef LOG_HEADER
  if( zLogFile
   && strstr(zScript,"FullHeaderLog")!=0
   && strlen(zLogFile)<sizeof(zLine)-50
  ){
    sprintf(zLine, "%s-hdr", zLogFile);
    hdrLog = fopen(zLine, "wb");
  }
#endif


  /* Get all the optional fields that follow the first line.
  */
  zCookie = 0;
  zAuthType = 0;
  zRemoteUser = 0;
  zReferer = 0;
  zIfNoneMatch = 0;
  zIfModifiedSince = 0;
  rangeEnd = 0;
  while( fgets(zLine,sizeof(zLine),stdin) ){
    char *zFieldName;
    char *zVal;

#ifdef LOG_HEADER
    if( hdrLog ) fprintf(hdrLog, "%s", zLine);
#endif
    nIn += strlen(zLine);
    zFieldName = GetFirstElement(zLine,&zVal);
    if( zFieldName==0 || *zFieldName==0 ) break;
    RemoveNewline(zVal);
    if( strcasecmp(zFieldName,"User-Agent:")==0 ){
      zAgent = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Accept:")==0 ){
      zAccept = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Accept-Encoding:")==0 ){
      zAcceptEncoding = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Content-length:")==0 ){
      zContentLength = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Content-type:")==0 ){
      zContentType = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Referer:")==0 ){
      zReferer = StrDup(zVal);
      if( strstr(zVal, "devids.net/")!=0 ){ zReferer = "devids.net.smut";
        Forbidden(230); /* LOG: Referrer is devids.net */
      }
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
      if( sanitizeString(zVal) ){
        Forbidden(240);  /* LOG: Illegal content in HOST: parameter */
      }
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
    }else if( strcasecmp(zFieldName,"If-None-Match:")==0 ){
      zIfNoneMatch = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"If-Modified-Since:")==0 ){
      zIfModifiedSince = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Range:")==0
           && strcmp(zMethod,"GET")==0 ){
      int x1 = 0, x2 = 0;
      int n = sscanf(zVal, "bytes=%d-%d", &x1, &x2);
      if( n==2 && x1>=0 && x2>=x1 ){
        rangeStart = x1;
        rangeEnd = x2;
      }else if( n==1 && x1>0 ){
        rangeStart = x1;
        rangeEnd = 0x7fffffff;
      }
    }
  }
#ifdef LOG_HEADER
  if( hdrLog ) fclose(hdrLog);
#endif

  /* Disallow requests from certain clients */
  if( zAgent ){
    const char *azDisallow[] = {
      "Windows 9",
      "Download Master",
      "Ezooms/",
      "HTTrace",
      "AhrefsBot",
      "MicroMessenger",
      "OPPO A33 Build",
      "SemrushBot",
      "MegaIndex.ru",
      "MJ12bot",
      "Chrome/0.A.B.C",
      "Neevabot/",
      "BLEXBot/",
    };
    size_t ii;
    for(ii=0; ii<sizeof(azDisallow)/sizeof(azDisallow[0]); ii++){
      if( strstr(zAgent,azDisallow[ii])!=0 ){
        Forbidden(250);  /* LOG: Disallowed user agent */
      }
    }
#if 0
    /* Spider attack from 2019-04-24 */
    if( strcmp(zAgent,
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36")==0 ){
      Forbidden(251);  /* LOG: Disallowed user agent (20190424) */
    }
#endif
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
      if( strstr(zReferer, azDisallow[i])!=0 ){
        NotFound(260);  /* LOG: Disallowed referrer */
      }
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
    size_t len = atoi(zContentLength);
    FILE *out;
    char *zBuf;
    int n;

    if( len>MAX_CONTENT_LENGTH ){
      StartResponse("500 Request too large");
      nOut += printf(
        "Content-type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Too much POST data\n"
      );
      MakeLogEntry(0, 270); /* LOG: Request too large */
      exit(0);
    }
    rangeEnd = 0;
    sprintf(zTmpNamBuf, "/tmp/-post-data-XXXXXX");
    zTmpNam = zTmpNamBuf;
    if( mkstemp(zTmpNam)<0 ){
      Malfunction(280,  /* LOG: mkstemp() failed */
               "Cannot create a temp file in which to store POST data");
    }
    out = fopen(zTmpNam,"wb");
    if( out==0 ){
      StartResponse("500 Cannot create /tmp file");
      nOut += printf(
        "Content-type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Could not open \"%s\" for writing\n", zTmpNam
      );
      MakeLogEntry(0, 290); /* LOG: cannot create temp file for POST */
      exit(0);
    }
    zBuf = SafeMalloc( len+1 );
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
  sanitizeString(zScript);

  /* Do not allow "/." or "/-" to to occur anywhere in the entity name.
  ** This prevents attacks involving ".." and also allows us to create
  ** files and directories whose names begin with "-" or "." which are
  ** invisible to the webserver.
  **
  ** Exception:  Allow the "/.well-known/" prefix in accordance with
  ** RFC-5785.
  */
  for(z=zScript; *z; z++){
    if( *z=='/' && (z[1]=='.' || z[1]=='-') ){
      if( strncmp(zScript,"/.well-known/",13)==0 && (z[1]!='.' || z[2]!='.') ){
        /* Exception:  Allow "/." and "/-" for URLs that being with
        ** "/.well-known/".  But do not allow "/..". */
        continue;
      }
      NotFound(300); /* LOG: Path element begins with "." or "-" */
    }
  }

  /* Figure out what the root of the filesystem should be.  If the
  ** HTTP_HOST parameter exists (stored in zHttpHost) then remove the
  ** port number from the end (if any), convert all characters to lower
  ** case, and convert non-alphanumber characters (including ".") to "_".
  ** Then try to find a directory with that name and the extension .website.
  ** If not found, look for "default.website".
  */
  if( zScript[0]!='/' ){
    NotFound(310); /* LOG: URI does not start with "/" */
  }
  if( strlen(zRoot)+40 >= sizeof(zLine) ){
    NotFound(320); /* LOG: URI too long */
  }
  if( zHttpHost==0 || zHttpHost[0]==0 ){
    NotFound(330);  /* LOG: Missing HOST: parameter */
  }else if( strlen(zHttpHost)+strlen(zRoot)+10 >= sizeof(zLine) ){
    NotFound(340);  /* LOG: HOST parameter too long */
  }else{
    sprintf(zLine, "%s/%s", zRoot, zHttpHost);
    for(i=strlen(zRoot)+1; zLine[i] && zLine[i]!=':'; i++){
      unsigned char c = (unsigned char)zLine[i];
      if( !isalnum(c) ){
        if( c=='.' && (zLine[i+1]==0 || zLine[i+1]==':') ){
          /* If the client sent a FQDN with a "." at the end
          ** (example: "sqlite.org." instead of just "sqlite.org") then
          ** omit the final "." from the document root directory name */
          break;
        }
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
        NotFound(350);  /* LOG: *.website permissions */
      }
    }
  }
  zHome = StrDup(zLine);

  /* Change directories to the root of the HTTP filesystem
  */
  if( chdir(zHome)!=0 ){
    char zBuf[1000];
    Malfunction(360,  /* LOG: chdir() failed */
         "cannot chdir to [%s] from [%s]",
         zHome, getcwd(zBuf,999));
  }

  /* Locate the file in the filesystem.  We might have to append
  ** a name like "/home" or "/index.html" or "/index.cgi" in order
  ** to find it.  Any excess path information is put into the
  ** zPathInfo variable.
  */
  j = j0 = (int)strlen(zLine);
  i = 0;
  while( zScript[i] ){
    while( zScript[i] && (i==0 || zScript[i]!='/') ){
      zLine[j] = zScript[i];
      i++; j++;
    }
    zLine[j] = 0;
    if( stat(zLine,&statbuf)!=0 ){
      int stillSearching = 1;
      while( stillSearching && i>0 && j>j0 ){
        while( j>j0 && zLine[j-1]!='/' ){ j--; }
        strcpy(&zLine[j-1], "/not-found.html");
        if( stat(zLine,&statbuf)==0 && S_ISREG(statbuf.st_mode)
            && access(zLine,R_OK)==0 ){
          zRealScript = StrDup(&zLine[j0]);
          Redirect(zRealScript, 302, 1, 370); /* LOG: redirect to not-found */
          return;
        }else{
          j--;
        }
      }
      if( stillSearching ) NotFound(380); /* LOG: URI not found */
      break;
    }
    if( S_ISREG(statbuf.st_mode) ){
      if( access(zLine,R_OK) ){
        NotFound(390);  /* LOG: File not readable */
      }
      zRealScript = StrDup(&zLine[j0]);
      break;
    }
    if( zScript[i]==0 || zScript[i+1]==0 ){
      static const char *azIndex[] = { "/home", "/index.html", "/index.cgi" };
      int k = j>0 && zLine[j-1]=='/' ? j-1 : j;
      unsigned int jj;
      for(jj=0; jj<sizeof(azIndex)/sizeof(azIndex[0]); jj++){
        strcpy(&zLine[k],azIndex[jj]);
        if( stat(zLine,&statbuf)!=0 ) continue;
        if( !S_ISREG(statbuf.st_mode) ) continue;
        if( access(zLine,R_OK) ) continue;
        break;
      }
      if( jj>=sizeof(azIndex)/sizeof(azIndex[0]) ){
        NotFound(400); /* LOG: URI is a directory w/o index.html */
      }
      zRealScript = StrDup(&zLine[j0]);
      if( zScript[i]==0 ){
        /* If the requested URL does not end with "/" but we had to
        ** append "index.html", then a redirect is necessary.  Otherwise
        ** none of the relative URLs in the delivered document will be
        ** correct. */
        Redirect(zRealScript,301,1,410); /* LOG: redirect to add trailing / */
        return;
      }
      break;
    }
    zLine[j] = zScript[i];
    i++; j++;
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
    char *zBaseFilename;         /* Filename without directory prefix */

    /*
    ** Abort with an error if the CGI script is writable by anyone other
    ** than its owner.
    */
    if( statbuf.st_mode & 0022 ){
      CgiScriptWritable();
    }

    /* If its executable, it must be a CGI program.  Start by
    ** changing directories to the directory holding the program.
    */
    if( chdir(zDir) ){
      char zBuf[1000];
      Malfunction(420, /* LOG: chdir() failed */
           "cannot chdir to [%s] from [%s]", 
           zDir, getcwd(zBuf,999));
    }

    /* Compute the base filename of the CGI script */
    for(i=strlen(zFile)-1; i>=0 && zFile[i]!='/'; i--){}
    zBaseFilename = &zFile[i+1];

    /* Setup the environment appropriately.
    */
    putenv("GATEWAY_INTERFACE=CGI/1.0");
    for(i=0; i<(int)(sizeof(cgienv)/sizeof(cgienv[0])); i++){
      if( *cgienv[i].pzEnvValue ){
        SetEnv(cgienv[i].zEnvName,*cgienv[i].pzEnvValue);
      }
    }
    if( useHttps ){
      putenv("HTTPS=on");
      putenv("REQUEST_SCHEME=https");
    }else{
      putenv("REQUEST_SCHEME=http");
    }

    /* For the POST method all input has been written to a temporary file,
    ** so we have to redirect input to the CGI script from that file.
    */
    if( zMethod[0]=='P' ){
      if( dup(0)<0 ){
        Malfunction(430,  /* LOG: dup(0) failed */
                    "Unable to duplication file descriptor 0");
      }
      close(0);
      open(zTmpNam, O_RDONLY);
    }

    if( strncmp(zBaseFilename,"nph-",4)==0 ){
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
      if( pipe(px) ){
        Malfunction(440, /* LOG: pipe() failed */
                    "Unable to create a pipe for the CGI program");
      }
      if( fork()==0 ){
        close(px[0]);
        close(1);
        if( dup(px[1])!=1 ){
          Malfunction(450, /* LOG: dup(1) failed */
                 "Unable to duplicate file descriptor %d to 1",
                 px[1]);
        }
        close(px[1]);
        for(i=3; close(i)==0; i++){}
        execl(zBaseFilename, zBaseFilename, (char*)0);
        exit(0);
      }
      close(px[1]);
      in = fdopen(px[0], "rb");
    }
    if( in==0 ){
      CgiError();
    }else{
      CgiHandleReply(in);
    }
  }else if( lenFile>5 && strcmp(&zFile[lenFile-5],".scgi")==0 ){
    /* Any file that ends with ".scgi" is assumed to be text of the
    ** form:
    **     SCGI hostname port
    ** Open a TCP/IP connection to that host and send it an SCGI request
    */
    SendScgiRequest(zFile, zScript);
  }else if( countSlashes(zRealScript)!=countSlashes(zScript) ){
    /* If the request URI for static content contains material past the
    ** actual content file name, report that as a 404 error. */
    NotFound(460); /* LOG: Excess URI content past static file name */
  }else{
    /* If it isn't executable then it
    ** must a simple file that needs to be copied to output.
    */
    if( SendFile(zFile, lenFile, &statbuf) ) return;
  }
  fflush(stdout);
  MakeLogEntry(0, 0);  /* LOG: Normal reply */

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
** Implement an HTTP server daemon listening on port zPort.
**
** As new connections arrive, fork a child and let the child return
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
    }else if( strcmp(z,"-max-age")==0 ){
      mxAge = atoi(zArg);
    }else if( strcmp(z,"-max-cpu")==0 ){
      maxCpu = atoi(zArg);
    }else if( strcmp(z,"-https")==0 ){
      useHttps = atoi(zArg);
      zHttp = useHttps ? "https" : "http";
      if( useHttps ) zRemoteAddr = getenv("REMOTE_HOST");
    }else if( strcmp(z, "-port")==0 ){
      zPort = zArg;
      standalone = 1;
     
    }else if( strcmp(z, "-family")==0 ){
      if( strcmp(zArg, "ipv4")==0 ){
        ipv4Only = 1;
      }else if( strcmp(zArg, "ipv6")==0 ){
        ipv6Only = 1;
      }else{
        Malfunction(500,  /* LOG: unknown IP protocol */
                    "unknown IP protocol: [%s]\n", zArg);
      }
    }else if( strcmp(z, "-jail")==0 ){
      if( atoi(zArg)==0 ){
        useChrootJail = 0;
      }
    }else if( strcmp(z, "-debug")==0 ){
      if( atoi(zArg) ){
        useTimeout = 0;
      }
    }else if( strcmp(z, "-input")==0 ){
      if( freopen(zArg, "rb", stdin)==0 || stdin==0 ){
        Malfunction(501, /* LOG: cannot open --input file */
                    "cannot open --input file \"%s\"\n", zArg);
      }
    }else if( strcmp(z, "-datetest")==0 ){
      TestParseRfc822Date();
      printf("Ok\n");
      exit(0);
    }else{
      Malfunction(510, /* LOG: unknown command-line argument on launch */
                  "unknown argument: [%s]\n", z);
    }
    argv += 2;
    argc -= 2;
  }
  if( zRoot==0 ){
    if( standalone ){
      zRoot = ".";
    }else{
      Malfunction(520, /* LOG: --root argument missing */
                  "no --root specified");
    }
  }
  
  /* Change directories to the root of the HTTP filesystem.  Then
  ** create a chroot jail there.
  */
  if( chdir(zRoot)!=0 ){
    Malfunction(530, /* LOG: chdir() failed */
                "cannot change to directory [%s]", zRoot);
  }

  /* Get information about the user if available */
  if( zPermUser ) pwd = getpwnam(zPermUser);

  /* Enter the chroot jail if requested */  
  if( zPermUser && useChrootJail && getuid()==0 ){
    if( chroot(".")<0 ){
      Malfunction(540, /* LOG: chroot() failed */
                  "unable to create chroot jail");
    }else{
      zRoot = "";
    }
  }

  /* Activate the server, if requested */
  if( zPort && http_server(zPort, 0) ){
    Malfunction(550, /* LOG: server startup failed */
                "failed to start server");
  }

#ifdef RLIMIT_CPU
  if( maxCpu>0 ){
    struct rlimit rlim;
    rlim.rlim_cur = maxCpu;
    rlim.rlim_max = maxCpu;
    setrlimit(RLIMIT_CPU, &rlim);
  }
#endif

  /* Drop root privileges.
  */
  if( zPermUser ){
    if( pwd ){
      if( setgid(pwd->pw_gid) ){
        Malfunction(560, /* LOG: setgid() failed */
                    "cannot set group-id to %d", pwd->pw_gid);
      }
      if( setuid(pwd->pw_uid) ){
        Malfunction(570, /* LOG: setuid() failed */
                    "cannot set user-id to %d", pwd->pw_uid);
      }
    }else{
      Malfunction(580, /* LOG: unknown user */
                  "no such user [%s]", zPermUser);
    }
  }
  if( getuid()==0 ){
    Malfunction(590, /* LOG: cannot run as root */
                "cannot run as root");
  }

  /* Get the IP address from whence the request originates
  */
  if( zRemoteAddr==0 ){
    address remoteAddr;
    unsigned int size = sizeof(remoteAddr);
    char zHost[NI_MAXHOST];
    if( getpeername(0, &remoteAddr.sa, &size)>=0 ){
      getnameinfo(&remoteAddr.sa, size, zHost, sizeof(zHost), 0, 0,
                  NI_NUMERICHOST);
      zRemoteAddr = StrDup(zHost);
    }
  }
  if( zRemoteAddr!=0
   && strncmp(zRemoteAddr, "::ffff:", 7)==0
   && strchr(zRemoteAddr+7, ':')==0
   && strchr(zRemoteAddr+7, '.')!=0
  ){
    zRemoteAddr += 7;
  }

  /* Process the input stream */
  for(i=0; i<100; i++){
    ProcessOneRequest(0);
  }
  ProcessOneRequest(1);
  exit(0);
}

#if 0
/* Copy/paste the following text into SQLite to generate the xref
** table that describes all error codes.
*/
BEGIN;
CREATE TABLE IF NOT EXISTS xref(lineno INTEGER PRIMARY KEY, desc TEXT);
DELETE FROM Xref;
INSERT INTO xref VALUES(100,'Malloc() failed');
INSERT INTO xref VALUES(110,'Not authorized');
INSERT INTO xref VALUES(120,'CGI Error');
INSERT INTO xref VALUES(130,'Timeout');
INSERT INTO xref VALUES(140,'CGI script is writable');
INSERT INTO xref VALUES(150,'Cannot open -auth file');
INSERT INTO xref VALUES(160,'http request on https-only page');
INSERT INTO xref VALUES(170,'-auth redirect');
INSERT INTO xref VALUES(180,'malformed entry in -auth file');
INSERT INTO xref VALUES(190,'chdir() failed');
INSERT INTO xref VALUES(200,'bad protocol in HTTP header');
INSERT INTO xref VALUES(210,'Empty request URI');
INSERT INTO xref VALUES(220,'Unknown request method');
INSERT INTO xref VALUES(230,'Referrer is devids.net');
INSERT INTO xref VALUES(240,'Illegal content in HOST: parameter');
INSERT INTO xref VALUES(250,'Disallowed user agent');
INSERT INTO xref VALUES(260,'Disallowed referrer');
INSERT INTO xref VALUES(270,'Request too large');
INSERT INTO xref VALUES(280,'mkstemp() failed');
INSERT INTO xref VALUES(290,'cannot create temp file for POST content');
INSERT INTO xref VALUES(300,'Path element begins with . or -');
INSERT INTO xref VALUES(310,'URI does not start with /');
INSERT INTO xref VALUES(320,'URI too long');
INSERT INTO xref VALUES(330,'Missing HOST: parameter');
INSERT INTO xref VALUES(340,'HOST parameter too long');
INSERT INTO xref VALUES(350,'*.website permissions');
INSERT INTO xref VALUES(360,'chdir() failed');
INSERT INTO xref VALUES(370,'redirect to not-found page');
INSERT INTO xref VALUES(380,'URI not found');
INSERT INTO xref VALUES(390,'File not readable');
INSERT INTO xref VALUES(400,'URI is a directory w/o index.html');
INSERT INTO xref VALUES(410,'redirect to add trailing /');
INSERT INTO xref VALUES(420,'chdir() failed');
INSERT INTO xref VALUES(430,'dup(0) failed');
INSERT INTO xref VALUES(440,'pipe() failed');
INSERT INTO xref VALUES(450,'dup(1) failed');
INSERT INTO xref VALUES(460,'Excess URI content past static file name');
INSERT INTO xref VALUES(470,'ETag Cache Hit');
INSERT INTO xref VALUES(480,'fopen() failed for static content');
INSERT INTO xref VALUES(2,'Normal HEAD reply');
INSERT INTO xref VALUES(0,'Normal reply');
INSERT INTO xref VALUES(500,'unknown IP protocol');
INSERT INTO xref VALUES(501,'cannot open --input file');
INSERT INTO xref VALUES(510,'unknown command-line argument on launch');
INSERT INTO xref VALUES(520,'--root argument missing');
INSERT INTO xref VALUES(530,'chdir() failed');
INSERT INTO xref VALUES(540,'chroot() failed');
INSERT INTO xref VALUES(550,'server startup failed');
INSERT INTO xref VALUES(560,'setgid() failed');
INSERT INTO xref VALUES(570,'setuid() failed');
INSERT INTO xref VALUES(580,'unknown user');
INSERT INTO xref VALUES(590,'cannot run as root');
INSERT INTO xref VALUES(600,'malloc() failed');
INSERT INTO xref VALUES(610,'malloc() failed');
COMMIT;
#endif /* SQL */

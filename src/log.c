#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include "ctf-pwn-server.h"

int prefix_printf(FILE* fp, char *level)
{
    va_list args;
    // variables to store the date and time components
    int hours, minutes, seconds, day, month, year;
    // `time_t` is an arithmetic time type
    time_t now = 0;
    // localtime converts a `time_t` value to calendar time and
    // returns a pointer to a `tm` structure with its members
    // filled with the corresponding values
    struct tm *local;
    size_t result;

    now = time(NULL);
    now = now + arg_time_offset;
    local = localtime(&now);

    hours = local->tm_hour;         // get hours since midnight (0-23)
    minutes = local->tm_min;        // get minutes passed after the hour (0-59)
    seconds = local->tm_sec;        // get seconds passed after a minute (0-59)
 
    day = local->tm_mday;            // get day of month (1 to 31)
    month = local->tm_mon + 1;      // get month of year (0 to 11)
    year = local->tm_year + 1900;   // get year since 1900

    result = fprintf(fp, "%04d-%02d-%02d %02d:%02d:%02d | %-7s | ", year, month, day, hours, minutes, seconds, level);

    return result;
}

int debug_printf(const char *format, ...)
{
    va_list args;
    size_t result;

    if(arg_verbose)
    {
        prefix_printf(stdout, "DEBUG");
        va_start(args, format);
        result = vfprintf (stdout, format, args);
        va_end (args);
    }
    
    return result;
}

int info_printf(const char *format, ...)
{
    va_list args;
    size_t result;

    prefix_printf(stdout, "INFO");
    va_start(args, format);
    result = vfprintf (stdout, format, args);
    va_end (args);
    return result;
}

int warning_printf(const char *format, ...)
{
    va_list args;
    size_t result;
    
    prefix_printf(stdout, "WARNING");
    va_start(args, format);
    result = vfprintf (stdout, format, args);
    va_end (args);
    return result;
}

int error_printf(const char *format, ...)
{
    va_list args;
    size_t result;
    
    prefix_printf(stderr, "ERROR");
    va_start(args, format);
    result = vfprintf (stderr, format, args);
    va_end (args);
    return result;
}
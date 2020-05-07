#include <errno.h>
#include "aiwendb.h"
#include <stdlib.h>
#include <string.h>
static size_t
awdb_strnlen(const char *s, size_t maxlen)
{
	size_t len;

	for (len = 0; len < maxlen; len++, s++) {
		if (!*s)
			break;
	}
	return (len);
}
static char *
awdb_strndup(const char *str, size_t n)
{
	size_t len;
	char *copy;

	len = awdb_strnlen(str, n);
	if ((copy = malloc(len + 1)) == NULL)
		return (NULL);
	memcpy(copy, str, len);
	copy[len] = '\0';
	return (copy);
}
int main(int argc, char **argv)
{
    
    char *filename = "IP_city_2020W16_single_WGS84.awdb"; //请正确填写文件路径 ，或者像埃文科技索要数据文件
    char *ip_address ="1.192.90.183";
    AWDB_s awdb;
    int status = AWDB_open(filename, AWDB_MODE_MMAP, &awdb);

    if (AWDB_SUCCESS != status) {
        fprintf(stderr, "\n  Can't open %s - %s\n",filename, AWDB_strerror(status));
        exit(1);
    }

    int gai_error, awdb_error;
    AWDB_lookup_result_s result =AWDB_lookup_string(&awdb, ip_address, &gai_error, &awdb_error);

    if (0 != gai_error) {
        fprintf(stderr,"\n  Error from getaddrinfo for %s - %s\n\n",ip_address, gai_strerror(gai_error));
        exit(2);
    }
	
    AWDB_entry_data_s entry_data;
char* buf=0;	
status =AWDB_get_value(&result.entry, &entry_data,"continent",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("洲:\t%s\n",buf);
 }
 
status =AWDB_get_value(&result.entry, &entry_data,"country",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("国家:\t%s\n",buf);
 }
 
status =AWDB_get_value(&result.entry, &entry_data,"accuracy",  NULL);
if (entry_data.has_data) { 
	char* buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("精度:\t%s\n",buf);
 }
 
 
 
status =AWDB_get_value(&result.entry, &entry_data,"zipcode",  NULL);
if (entry_data.has_data) { 
	char* buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("zipcode:\t%s\n",buf);
 }
 
 
status =AWDB_get_value(&result.entry, &entry_data,"timezone",  NULL);
if (entry_data.has_data) { 
	char* buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("时区:\t%s\n",buf);
 }
 
 
 status =AWDB_get_value(&result.entry, &entry_data,"prov",  NULL);
if (entry_data.has_data) { 
	char* buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("省:\t%s\n",buf);
 }
 
 
 status =AWDB_get_value(&result.entry, &entry_data,"city",  NULL);
if (entry_data.has_data) { 
	char* buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("城市:\t%s\n",buf);
 }
 
}


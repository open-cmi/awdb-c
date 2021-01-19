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
    
    char *filename = "awdb2.awdb"; //请正确填写文件路径 ，或者向埃文科技索要数据文件
    char *ip_address ="166.111.4.100";
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
	if (!result.found_entry) {
		printf("no results..没有查询到结果\n");
		exit(2);
	}
	
AWDB_entry_data_s entry_data;
char* buf=0;	
status =AWDB_get_value(&result.entry, &entry_data,"continent",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("洲:\t%s\n",buf);
 }
 
 status =AWDB_get_value(&result.entry, &entry_data,"areacode",  NULL);
 if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("国家编码:\t%s\n",buf);
 }

status =AWDB_get_value(&result.entry, &entry_data,"country",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("国家:\t%s\n",buf);
 }
 
status =AWDB_get_value(&result.entry, &entry_data,"zipcode",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("邮编:\t%s\n",buf);
 }

status =AWDB_get_value(&result.entry, &entry_data,"timezone",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("时区:\t%s\n",buf);
 }

status =AWDB_get_value(&result.entry, &entry_data,"accuracy",  NULL);
if (entry_data.has_data) { 

	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("定位精度:\t%s\n",buf);
 }
 
status =AWDB_get_value(&result.entry, &entry_data,"source",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("定位方式:\t%s\n",buf);
 }
 

status =AWDB_get_value(&result.entry, &entry_data,"province",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("省:\t%s\n",buf);
 }
 
status =AWDB_get_value(&result.entry, &entry_data,"city",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("城市:\t%s\n",buf);
 }
  
status =AWDB_get_value(&result.entry, &entry_data,"district",  NULL);
if (entry_data.has_data) { 


	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("区县:\t%s\n",buf); 
 }
 
status =AWDB_get_value(&result.entry, &entry_data,"lngwgs",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("WGS84坐标系经度:\t%s\n",buf);
 }

status =AWDB_get_value(&result.entry, &entry_data,"latwgs",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("WGS84坐标系纬度:\t%s\n",buf);
 }

status =AWDB_get_value(&result.entry, &entry_data,"radius",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("定位半径:\t%s\n",buf);
 }


status =AWDB_get_value(&result.entry, &entry_data,"isp",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("运营商:\t%s\n",buf);
 }

status =AWDB_get_value(&result.entry, &entry_data,"asnumber",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("AS号:\t%s\n",buf);
 }


status =AWDB_get_value(&result.entry, &entry_data,"owner",  NULL);
if (entry_data.has_data) { 
	buf=awdb_strndup((char*)entry_data.utf8_string,entry_data.data_size);
	printf("拥有者:\t%s\n",buf);
 }


 //打印全部信息
AWDB_entry_data_list_s *entry_data_list = NULL;
AWDB_entry_s entry ={ .awdb = &awdb, .offset = result.entry.offset };
status = AWDB_get_entry_data_list(&entry, &entry_data_list);
													  
AWDB_dump_entry_data_list(stdout, entry_data_list, 2);
 
}


/*
** Zabbix
** Copyright (C) 2001-2023 Zabbix SIA
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**/

#ifndef ZABBIX_STR_H
#define ZABBIX_STR_H

#include "zbxcommon.h"

char	*zbx_string_replace(const char *str, const char *sub_str1, const char *sub_str2);

int	zbx_is_ascii_string(const char *str);

int	zbx_rtrim(char *str, const char *charlist);
void	zbx_ltrim(char *str, const char *charlist);
void	zbx_lrtrim(char *str, const char *charlist);
void	zbx_remove_chars(char *str, const char *charlist);
char	*zbx_str_printable_dyn(const char *text);
#define ZBX_WHITESPACE			" \t\r\n"
void	zbx_del_zeros(char *s);

size_t	zbx_get_escape_string_len(const char *src, const char *charlist);
char	*zbx_dyn_escape_string(const char *src, const char *charlist);
int	zbx_escape_string(char *dst, size_t len, const char *src, const char *charlist);

int	zbx_str_in_list(const char *list, const char *value, char delimiter);
int	zbx_str_n_in_list(const char *list, const char *value, size_t len, char delimiter);

char	*zbx_str_linefeed(const char *src, size_t maxline, const char *delim);
void	zbx_strarr_init(char ***arr);
void	zbx_strarr_add(char ***arr, const char *entry);
void	zbx_strarr_free(char ***arr);

void	zbx_strcpy_alloc(char **str, size_t *alloc_len, size_t *offset, const char *src);
void	zbx_chrcpy_alloc(char **str, size_t *alloc_len, size_t *offset, char c);
void	zbx_str_memcpy_alloc(char **str, size_t *alloc_len, size_t *offset, const char *src, size_t n);
void	zbx_strquote_alloc(char **str, size_t *str_alloc, size_t *str_offset, const char *value_str);

void	zbx_strsplit_first(const char *src, char delimiter, char **left, char **right);
void	zbx_strsplit_last(const char *src, char delimiter, char **left, char **right);

/* secure string copy */
#define zbx_strscpy(x, y)	zbx_strlcpy(x, y, sizeof(x))
#define zbx_strscat(x, y)	zbx_strlcat(x, y, sizeof(x))
void	zbx_strlcat(char *dst, const char *src, size_t siz);
size_t	zbx_strlcpy_utf8(char *dst, const char *src, size_t size);

char	*zbx_strdcat(char *dest, const char *src);
char	*zbx_strdcatf(char *dest, const char *f, ...) __zbx_attr_format_printf(2, 3);

const char	*zbx_truncate_itemkey(const char *key, const size_t char_max, char *buf, const size_t buf_len);
const char	*zbx_truncate_value(const char *val, const size_t char_max, char *buf, const size_t buf_len);

#define ZBX_NULL2STR(str)	(NULL != str ? str : "(null)")
#define ZBX_NULL2EMPTY_STR(str)	(NULL != (str) ? (str) : "")

char	*zbx_strcasestr(const char *haystack, const char *needle);
int	zbx_strncasecmp(const char *s1, const char *s2, size_t n);
int	zbx_strcasecmp(const char *s1, const char *s2);

#if defined(_WINDOWS) || defined(__MINGW32__)
char	*zbx_unicode_to_utf8(const wchar_t *wide_string);
char	*zbx_unicode_to_utf8_static(const wchar_t *wide_string, char *utf8_string, int utf8_size);
#endif

void	zbx_strlower(char *str);
void	zbx_strupper(char *str);

#if defined(_WINDOWS) || defined(__MINGW32__) || defined(HAVE_ICONV)
char	*zbx_convert_to_utf8(char *in, size_t in_size, const char *encoding);
#endif	/* HAVE_ICONV */

#define ZBX_MAX_BYTES_IN_UTF8_CHAR	4
size_t	zbx_utf8_char_len(const char *text);
size_t	zbx_strlen_utf8(const char *text);
char	*zbx_strshift_utf8(char *text, size_t num);
size_t	zbx_strlen_utf8_nchars(const char *text, size_t utf8_maxlen);
size_t	zbx_charcount_utf8_nbytes(const char *text, size_t maxlen);

int	zbx_is_utf8(const char *text);
void	zbx_replace_invalid_utf8(char *text);

void	zbx_dos2unix(char *str);

int	zbx_replace_mem_dyn(char **data, size_t *data_alloc, size_t *data_len, size_t offset, size_t sz_to,
		const char *from, size_t sz_from);

void	zbx_trim_str_list(char *list, char delimiter);

int	zbx_strcmp_null(const char *s1, const char *s2);

char	*zbx_dyn_escape_shell_single_quote(const char *arg);

int	zbx_strcmp_natural(const char *s1, const char *s2);
int	zbx_str_extract(const char *text, size_t len, char **value);
char	*zbx_substr(const char *src, size_t left, size_t right);
char	*zbx_substr_unquote(const char *src, size_t left, size_t right);

/* UTF-8 trimming */
void	zbx_ltrim_utf8(char *str, const char *charlist);
void	zbx_rtrim_utf8(char *str, const char *charlist);

void	zbx_strncpy_alloc(char **str, size_t *alloc_len, size_t *offset, const char *src, size_t n);
void	zbx_replace_string(char **data, size_t l, size_t *r, const char *value);

/**
 * 拆分字符串
 * src 被拆分的字符串
 * separator 分割符
 * dest 拆分结果
 * num 拆分后结果长度
 * 返回:SUCCEED 和 FAIL
 如：
	int num = 22;
	char *tokens[22] = {0};
	char *bstr= "123#abc#h932";
	zbx_split(bstr, "#", tokens, &num);
*/
int zbx_split(char *src, const char *separator, char **dest, int *num);

/**
 * 把字符串转为整型
 * dst 被转化的字符串
 * 返回: 如果字符串为NULL或非法字符串：0 , 正常：数字
 如： 
	char *bstr = "abc";
	int count = zbx_atoi(bstr);
	count 值为0
*/
int zbx_atoi(char *dst);

long zbx_atol(char *dst);

char *zbx_itoa(int value);

/**
 * 返回非NULL字符串，如果原来字符串是NULL，则返回""
*/
char * get_str_field(char *str);

/**
 * 判断字符串是否是数字组成
*/
int isdigitstr(char *str);

/**
 * 从最右边根据'split'拆分字符串,输出左边字符串到lstr,输出右边字符串到rstr;
 * 如：str = "ruijie-switch-6", split='-'; 输出:lstr="ruijie-switch",rstr="6"
*/
int zbx_strrchr(char *str, char split, char **lstr, char **rstr);

/**
 * 函数搜索一个字符串在另一个字符串中的第一次出现。比原生的增加了空指针判断
 * str1: 被查找目标
 * str2: 要查找对象
 * return: 找到所搜索的字符串，则该函数返回第一次匹配的字符串的地址； 如果未找到所搜索的字符串，则返回NULL。
*/
char *zbx_strstr(char *str1, const char *str2);

/**
 * 把字符串的版本号转为整形
 * 如:"1.3.2" 转为 10302
*/
int get_version(char *version);
#endif /* ZABBIX_STR_H */

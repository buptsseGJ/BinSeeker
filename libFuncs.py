#-*- coding: utf-8 -*-
import math
import sys
import os
import random

libFuncsList = [".sqrt", ".abs", ".rand",".cabs",".fabs",".labs",".exp",".frexp",".ldexp",".log",".log10",".pow",".pow10",".acos",".asin",".atan",".atan2",".cos",".sin",".tan",".cosh",".sinh",".tanh",".hypot",".ceil",".floor",".fmod",".modf",".strcmp"]
char_return_type = ['peekb','stpcpy','strcat','strchr','strcpy','strdup','strlwr','strncat','strncpy','strnset','strpbrk','strrchr','strrev','strset','strstr','strtok','strupr']
char_pointer_return_type = ['ecvt','fcvt','gcvt','ultoa','ltoa','itoa','getcwd','mktemp','searchpath','ecvt','fcvt','gcvt','ultoa','ltoa','itoa','strerror','cgets','fgets','parsfnm','getdta',
'sbrk','ctime','asctime']
int_return_type = ['isalpha','isalnum','isascii','iscntrl','isdigit','isgraph','islower','isprint','ispunct','isspace','isupper','isxdigit','tolower','toupper','abs','rand','atoi',
'matherr','chdir','findfirst','findnext','fnsplit','getcurdir','getdisk','setdisk','mkdir','rmdir','execl','execle','execlp','execlpe','execv','execve','execvp','execvpe','spawnl',
'spawnle','spawnlp','spawnlpe','spawnv','spawnve','spawnvp','spawnvpe','system','atoi','toascii','tolower','_tolower','toupper','_toupper','matherr','kbhit','fgetchar','getch','putch',
'getchar','putchar','getche','ungetch','scanf','vscanf','cscanf','sscanf','vsscanf','puts','printf','vprintf','cprintf','vcprintf','sprintf','vsprintf','rename','ioctl','gsignal','_open','open','creat','_creat',
'creatnew','creattemp','read','_read','write','_write','dup','dup2','eof','setmode','getftime','setftime','isatty','lock','unlock','close','_close','getc','putc','getw','putw','ungetc','fgetc',
'fgetc','fputc','fputs','fread','fwrite','fscanf','vfscanf','fprintf','vfprintf','fseek','rewind','feof','fileno','ferror','fclose','fcloseall','fflush','fflushall','access','chmod','_chmod','unlink',
'absread','abswrite','bdos','bdosptr','int86','int86x','intdos','intdosx','inport','inportb','peek','randbrd','randbwr','getverify','getcbrk','setcbrk','dosexterr','bioscom','biosdisk',
'biodquip','bioskey','biosmemory','biosprint','biostime','memicmp','strcmp','strcspn','stricmp','strlen','strncmp','strnicmp','strspn','allocmem','freemem','setblock','brk','stime']
int_unsigned_return_type = ['_clear87','_status87','sleep','FP_OFF','FP_SEG','getpsp']
double_return_type = ['cabs','fabs','exp','frexp','ldexp','log','log10','pow','pow10','sqrt','acos','asin','atan','atan2','cos','sin','tan','cosh','sinh','tanh','hypot','ceil','floor','poly',
'modf','fmod','frexp','atof','atoi','atol','atof','strtod','_matherr','atof','strtod','_matherr','difftime']
long_return_type = ['labs','atol','strtol','atol','strtol','filelength','lseek','tell','ftell','coreleft','farcoreleft','dostounix']
file_pointer_return_type = ['fopen','fdopen','freopen']
linux_lib = ['__errno_location']

random.seed(10)

def lib_abs(i):#int      abs(int i)                    返回整型参数i的绝对值
    return abs(i)#abs是内置函数

def lib_rand():#int     rand() 产生一个随机数并返回这个数
    random.seed(10)
    return random.randint(0,32767)

def lib_cabs(znum):#double  cabs(struct complex znum)      返回复数znum的绝对值
    return abs(znum)

def lib_fabs(x):#double  fabs(double x)                 返回双精度参数x的绝对值
    return abs(x)

def lib_labs(n):#long    labs(long n)                   返回长整型参数n的绝对值
    return abs(n)

def lib_exp(x):#double   exp(double x)                 返回指数函数e^x的值
    return math.exp(x)

def lib_frexp(value, eptr):#double frexp(double value,int *eptr)   返回value=x*2n中x的值,n存贮在eptr中
    return math.frexp(value)#math.frexp(1.625) 结果(0.8125,1) 

def lib_ldexp(value,exp):#double ldexp(double value,int exp);    返回value*2exp的值
    return math.ldexp(value, exp)

def lib_log(x):#double   log(double x)                 返回ln(x)的值
    return math.log(x)

def lib_log10(x):#double log10(double x)                 返回log10(x)的值
    return math.log10(x)

def lib_pow(x,y):#double   pow(double x,double y)        返回x^y的值
    return math.pow(x, y)

def lib_pow10(p):#double pow10(int p)                    返回10^p的值
    return math.pow(10, p)

def lib_sqrt(x):#double  sqrt(double x)                 返回x的正平方根
    return math.sqrt(x)

def lib_acos(x):#double  acos(double x)                 返回x的反余弦cos-1(x)值,x为弧度
    return math.acos(x)

def lib_asin(x):#double  asin(double x)                 返回x的反正弦sin-1(x)值,x为弧度
    return math.asin(x)

def lib_atan(x):#double  atan(double x)                 返回x的反正切tan-1(x)值,x为弧度
    return math.atan(x)

def lib_atan2(y,x):#double atan2(double y,double x)        返回y/x的反正切tan-1(x)值,y的x为弧度
    return math.atan2(y, x)

def lib_cos(x):#double   cos(double x)                 返回x的余弦cos(x)值,x为弧度
    return math.cos(x)

def lib_sin(x):#double   sin(double x)                 返回x的正弦sin(x)值,x为弧度
    return math.sin(x)

def lib_tan(x):#double   tan(double x)                 返回x的正切tan(x)值,x为弧度
    return math.tan(x)

def lib_cosh(x):#double  cosh(double x)                 返回x的双曲余弦cosh(x)值,x为弧度
    return math.cosh(x)

def lib_sinh(x):#double  sinh(double x)                 返回x的双曲正弦sinh(x)值,x为弧度
    return math.sinh(x)

def lib_tanh(x):#double  tanh(double x)                 返回x的双曲正切tanh(x)值,x为弧度
    return math.tanh(x)

def lib_hypot(x,y):#double hypot(double x,double y)        返回直角三角形斜边的长度(z),x和y为直角边的长度,z2=x2+y2
    return math.hypot(x, y)

def lib_ceil(x):#double  ceil(double x)                 返回不小于x的最小整数
    return math.ceil(x)

def lib_floor(x):#double floor(double x)                 返回不大于x的最大整数
    return math.floor(x)

def lib_poly(x, n, c):#double  poly(double x,int n,double c[])从参数产生一个多项式
    pass
    
def lib_fmod(x,y):#double  fmod(double x,double y)        返回x/y的余数
    return math.fmod(x, y)

def lib_modf(value, iptr):#double  modf(double value,double *iptr)将双精度数value分解成尾数和阶
    return math.modf(value)#小数是返回值，整数放在iptr地址中，需要特殊的关注
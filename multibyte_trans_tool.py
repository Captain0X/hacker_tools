# -*- coding: utf-8 -*-
'''
 @author : Captain0X
 @time : 2022/11/21 16:54
 '''
from string import punctuation

def trans_multi_encoding(char_str):
    multi_char=""
    for char in char_str:
        if char in punctuation:
            multi_char+=bytes('\\u56' +'%02x' % ord(char),encoding="utf-8").decode('raw_unicode_escape')
        else:
            multi_char+=char
    print('-------------------------------\noutput:\n',multi_char)
banner="""
input:
<% =7 * 7 %>

output:
嘼嘥 嘽7 嘪 7 嘥嘾
you can copy this result to burp ,burp will trans to code auto~
        tools_code_by_Captain0X

"""
print(banner)
while True:
    code=input("please input your code(input 0 exit):")
    if code=='0':
        exit()
    trans_multi_encoding(code)

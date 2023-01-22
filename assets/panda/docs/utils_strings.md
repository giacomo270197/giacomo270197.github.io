---
title: Utils Strings
permalink: /panda/docs/utils_strings
permalink_name: UtilsStrings
---

A library that contains functions used for working with strings.  

<br/>

`int strlen(string str)`  

The function takes a string as an input, and return the length of the string excluding the NULL terminator.  

<br/>

`int strcmp(string str1, string str2)`  

The function takes two strings as input and returns 1 if the strings are equal, and 0 otherwise.  

<br/>

`int strcat(string str1, string str2)`  

The function takes two strings as input and returns a new string that is the result of the concatenation of the two. Note that the function will allocate heap memory and create the new string in it.  

<br/>

`int strrvr(string str1, int in_place)`  

The function takes a string as an input and returns the reverse of it. The "in_place" parameter determines where the new result will be stored. A value of 1 reverses the string on the stack and modifies the original. A value of 0 will allocate space on the heap and create a new string there.
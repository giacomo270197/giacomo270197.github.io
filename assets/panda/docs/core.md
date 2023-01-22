---
title: Panda specifications
permalink: /panda/docs/core
permalink_name: PandaSpecs
---

## Syntax

Panda is a semi-colon terminated language. The usage is similar to C, and semi-colons are required where C would also require them. White spaces are generally ignored unless used within a quoted string.  

<br/>

# Data types

Panda uses only 4 data types.

`int`  
Represents a pointer-sized value. This can be used to hold actual integers, poiners, handles, ... Any numerical value, really.  

Example: `int variable = 4;`


`string`  
Represent an ASCII string, each character is byte-sized. It is created as a stack string by pushing the conent in revese to the stack. NULL-terminated.

Example: `string variable = "Hello World";`


`array int`  
A constant sized array of `int` values. It is also created by pushing the content to the stack in reverse. The array can be created both with initialized and uninitialized values.

Example: `array variable = int{1, 2, 3, 4};` or `array variable int[4];`


`array byte`  
A constant sized array of byte values. Similar to strings, but allows to use non-printable charachters. This can also be used to create C style structs. The array can be created both with initialized and uninitialized values.

Example: `array variable = byte{1, 2, 3, 4};` or `array variable byte[4];`

<br/>

The data types available give direct control over pointer-sized and byte values. In order to modify WORD values (and DWORD values in 64 bits) specific rotation and shifting operators are provided. `string` and `array` types can be index into with the usual `[index]` format.  

<br>

# Variables

A variable must always be declared before use. Variables can be declared at any point during a specific function logic but regardless of where it is declared space will be allocated for it on the stack.  

Declaration happens similarly as C, by simply stating the type of the variable in front of it upon first usage.  
For array types, only the keywork `array` has to be specified. The arrays can be then created with by specifying a size in square brakets or by specifing the actual elements in the array in curly brackets. Either way the keyword `int` or `byte` must be prepended to the braket to speciy the array type.

It is also possible to case a variable to a different type when required. This doesn't add any code, it only informs the compile that the variable should be used as a different type one. This can be done with an assignment to a new type.

Examples:  
```
int a = 5;
string b = "Hello World";
array c int[5];
array d = int{1, 2, 3, 4, 5};
array e byte[5];
array f = byte{1, 2, 3, 4, 5};
f = int;
```

# Operators

## Arithmetic and logic operators

`+`  
The plus sign always performs an addition. The right hand operand must always be a variable of type `int` or a constant numeric value. The operator can be used to add integers together or to add values to pointer for indexing into an array.

`-`  
The minus sign always performs a subtraction. The right hand operand must always be a variable of type `int` or a constant numeric value. The operator can be used to subtract an integer from another one or to subtract values to pointer for indexing into an array.

`*`  
The star sign performs a multiplication between two numerical values.

`/`  
The forward slash sign performs a division between two numerical values.

`&&`  
The double ampersand sign performs a bitwise AND between to numerical values.

`||`  
The double vertical bar represents a bitwise OR between two numerical values.

`^`  
The caret sign performs a bitwise XOR between two values.

`!`  
The exclamation mark sign, prepended to a value, performs a bitwise negation.

Examples:  
```
int a = 5;
int b = 4;
int c;
c = a + b;
c = a - b;
c = a * b;
c = a / b;
c = a && b;
c = a || b;
c = a  ^ b;
c = !a;
```

## Memory access operators

`*`  
The star sign, prepended to a value, returns the variable-sized value contained at the given address. It can also be used to write a value to a particular memory location.  

Examples:  
```
string a = "Hello World";
int b = *(a + 2);
```  
Writes a zero-padded byte value, corresponding with the ASCII number for "l" into b. An array of bytes behaves similarly.
```
array a = int{1, 2, 3, 4};
int b = *(a + 2);
```  
Writes a full pointer-sized value to b, in this case the number 3.
```
string a = "Hello World";
string b = "Beautiful day";
a[3] = b[0];
```
Writes a single byte into the a string, in this case it changes the "l" charachter with the "B" one from string b. Note that `a[3]` is equivalent to `*(a+3)`.

`&`  
The single ampersand operator is used to get the address of a variable.
Note that for arrays and strings that already are pointers, the operator returns the location of the pointer to the string or array. So it becomes a pointer to a pointer.

## Bit shifting operators

`ror`  
The operator performs a right bit rotation of a specified number of steps. It assumes a pointer-sized operand size.  

`ror16`  
Similar to `ror`, but assumes a WORD sized operand size. This can be useful to modify WORD values within a 32 or 64 bit valriable.

`rol`  
The operator performs a left bit rotation of a specified number of steps. It assumes a pointer-sized operand size.  

`rol16`  
Similar to `rol`, but assumes a WORD sized operand size. This can be useful to modify WORD values within a 32 or 64 bit valriable.

`shr`  
Performs a right bit shift of a specified numbers of steps. Values are 0 padded and overflowing bits are discarded.

`shl`  
Performs a left bit shift of a specified numbers of steps. Values are 0 padded and overflowing bits are discarded.

Examples:  
```
int a = 5;
int b = 8;
int c;
c = a ror b;
c = a ror16 b;
c = a rol b;
c = a rol16 b;
c = a shr b;
c = a shl b;
```

## Comparision operators

Comparision operators are `>`, `>=`, `<`, `<=`, `==`, `!=` and their usege is similar to other languages.  
Note that Panda does not have a concept of Boolean value, so statements like `int c = a < b;` are not valid and will produce unexpected results. Comparison operators are to be used with with `if` and `while` statements only.  

<br/>


# Control flow

## Functions

Functions are defined with the `fn` keyword and given a type. The function definition is otherwise similar to C with parameters in parenthesis in the "type name" format, and code enclosed in curly brakets. For exmple:

```
int fn ThisIsAFunc(string str, int num) {
    ...
}
```

Functions return with the `return` value, which must always return a value.  
Note that, despite functions having a type, that currently means nothig since the value returned is always a pointer-sized value regardless.  

Each program should have exactly one `main` function defined to start execution from.

## If-statements

Similar to if-statements in other languages and follow the C syntax.

```
if(condition) {
    ...
} else {

}
```

Else-if statements are currently not implemented so a nested if-statement is required to acheive the same result.

## Loops

Currently, only while loops are implemented, and once again they mostly follow C syntax and behavior.

```
while(condition) {

}
```

No for-loops are present in Panda at the moment.  

<br/>

# Importing external code

## Imports

Imports are defined with the `import` statement and should be placed at the beginning of the code, outside any function definition. The import is then specified with a "." joined path to the Panda source code file from which functions must be imported. So for example

```
import libraries.utils.strings
```

would import all the functions defined under `\libraries\utils\strings.pnd`. Note that the extenstion should be omitted.  
While all functions are imported, only the ones that are actually used end up in the final shellcode.  
It is important that no `main` function is defined in these libraries. 


## Windows API functions

Windows API functions can be imported with the `declare` statement, which accepts the function name and the DLL it is contained in as parameters. For example
```
declare("MessageBoxA", "user32.dll");
```
`declare` statements must be placed at the top of the source file, before anything else, including imports.  
Once a function is declared, it will then become available just as if it was any other function. So in the previous example it would be possible to call the function simply as
```
string a = "Text";
string b = "Caption";
MessageBoxA(0, a, b, 0);
```

Once any declare is added, two functions will be resolved automatically and will be available without specific declaring. `LoadLibraryA` will be resolved so that the compiler can automatically load modules that contain new function declarations. `TerminateProcess` wil also be resolved.
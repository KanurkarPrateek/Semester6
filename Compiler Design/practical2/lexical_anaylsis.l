%{
#include<stdio.h>
%}

keyword  "abstract"|"assert"|"boolean"|"break"|"byte"|"case"|"catch"|"char"|"class"|"const"|"continue"|"default"|"do"|"double"|"else"|"enum"|"extends"|"final"|"finally"|"float"|"for"|"public"|"static"|"void"
string \".*\"
char [a-zA-Z]
digit [0-9]
identifier {char}({digit}|{char})*
punctuation [.,;:(){}[\]]
binary_operator [-+\*/=<>!&|^%]
ternary_operator [?]
logical_operator [\"&&"\"||"]

%%

{keyword} {printf("keyword = %s\n", yytext);}
{string} {printf("string = %s\n", yytext);}
{digit} {printf("digit = %s\n", yytext);}
{identifier} {printf("identifier = %s\n", yytext);}
{punctuation} {printf("punctuation = %s\n", yytext);}
{binary_operator} {printf("binary_operator = %s\n", yytext);}
{ternary_operator} {printf("ternary_operator = %s\n", yytext);}
{logical_operator} {printf("logical_operator = %s\n", yytext);}

%%

int main() {
    yyin=fopen("input.java","r");
    yylex();
    fclose(yyin);
    return 0;
}

int yywrap() {
    return 1;
}

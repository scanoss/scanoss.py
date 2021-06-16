# Winnowing

SCANOSS implements an adaptation of the original winnowing algorithm by S. Schleimer, D. S. Wilkerson and A. Aiken
as described in their seminal article which can be found here: [https://theory.stanford.edu/~aiken/publications/papers/sigmod03.pdf](https://theory.stanford.edu/~aiken/publications/papers/sigmod03.pdf)

The winnowing algorithm is configured using two parameters, the gram size and the window size. For SCANOSS the values need to be:

- GRAM: 30
- WINDOW: 64

The result of performing the Winnowing algorithm is a string called **WFP** (_Winnowing FingerPrint_). A WFP contains optionally
the name of the source component and the results of the Winnowing algorithm for each file.

EXAMPLE output: test-component.wfp

```
component=f9fc398cec3f9dd52aa76ce5b13e5f75,test-component.zip
file=cae3ae667a54d731ca934e2867b32aaa,948,test/test-file1.c
4=579be9fb
5=9d9eefda,58533be6,6bb11697
6=80188a22,f9bb9220
10=750988e0,b6785a0d
12=600c7ec9
13=595544cc
18=e3cb3b0f
19=e8f7133d
file=cae3ae667a54d731ca934e2867b32aaa,1843,test/test-file2.c
2=58fb3eed
3=f5f7f458
4=aba6add1
8=53762a72,0d274008,6be2454a
10=239c7dfa
12=0b2188c9
15=bd9c4b10,d5c8f9fb
16=eb7309dd,63aebec5
19=316e10eb
[...]
```

Here, component is the MD5 hash and path of the component (It could be a path to a compressed file or a URL).
file is the MD5 hash, file length and file path being fingerprinted, followed by
a list of WFP fingerprints with their corresponding line numbers.

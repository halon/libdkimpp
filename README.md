libdkim++ is a lightweight and portable DKIM (RFC6376) library for *NIX,
supporting both signing and DMARC/ARC/SDID verification sponsored and
used by Halon Security's (http://halon.io) SMTP platform.
libdkim++ has extensive unit test coverage and aims to fully comply with
the current RFC.

[![Coverity Scan Build](https://img.shields.io/coverity/scan/7286.svg)](https://scan.coverity.com/projects/halonsecurity-libdkimpp)

Building
--------
This library requires CMake (http://www.cmake.org/) to compile, and
depends on OpenSSL (which is normally shipped with *NIX distributions).

```
$ cmake .
$ make && make install
```

You might need to add some packages, like a C++ compiler and `cppunit`
which can be done by running `pkg_add -r cppunit`,
`apt-get install cppunit` or `yum install cppunit-devel` depending
on operating system.

* cmake
* pkg-config
* cppunit
* libssl-dev
* libsodium

Because some systems (like OpenBSD) lacks a reentrant resolver, this
library might not be thread-safe on all platforms.

Testing
-------
libdkim++ has extensive unit test coverage and aims to fully comply
with the current RFC.

```
$ make test
```

which should result in this output:

```
Running tests...
Test project /home/erik/Desktop/libdkimpp/build
   Start 1: QuotedPrintableTest
1/8 Test #1: QuotedPrintableTest ..............   Passed    0.00 sec
   Start 2: Base64Test
2/8 Test #2: Base64Test .......................   Passed    0.00 sec
   Start 3: CanonicalizationTest
3/8 Test #3: CanonicalizationTest .............   Passed    0.00 sec
   Start 4: MailParserTest
4/8 Test #4: MailParserTest ...................   Passed    0.00 sec
   Start 5: TokenizerTest
5/8 Test #5: TokenizerTest ....................   Passed    0.00 sec
   Start 6: EncodedWordTest
6/8 Test #6: EncodedWordTest ..................   Passed    0.00 sec
   Start 7: SignatoryTest
7/8 Test #7: SignatoryTest ....................   Passed    0.04 sec
   Start 8: TagListTest
8/8 Test #8: TagListTest ......................   Passed    0.00 sec
100% tests passed, 0 tests failed out of 8
Total Test time (real) =   0.08 sec
```

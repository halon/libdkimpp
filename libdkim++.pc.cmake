prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=${prefix}
libdir=${exec_prefix}/lib@LIB_SUFFIX@
includedir=${prefix}/include

Name: libdkim++
Description: libdkim++ is a lightweight and portable DKIM (RFC4871)
Version: @TARGET_VERSION@
Libs: -L${libdir} -ldkim++
Cflags: -I${includedir}

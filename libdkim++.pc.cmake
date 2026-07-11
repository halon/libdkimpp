prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=${prefix}
libdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@
includedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@

Name: libdkim++
Description: libdkim++ is a lightweight and portable DKIM (RFC4871)
Version: @TARGET_VERSION@
Libs: -L${libdir} -ldkim++
Cflags: -I${includedir}

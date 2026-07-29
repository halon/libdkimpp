prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=${prefix}
libdir=${exec_prefix}/@CMAKE_INSTALL_LIBDIR@
includedir=${prefix}/@CMAKE_INSTALL_INCLUDEDIR@

Name: libdkim++
Description: libdkim++ is a lightweight and portable DKIM (RFC6376)
Version: @TARGET_VERSION@
Requires.private: libssl libcrypto libsodium
Libs: -L${libdir} -ldkim++
Cflags: -I${includedir}

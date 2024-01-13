
LICENSE = "CLOSED"
SRC_URI = "file://S99aesdsocket"

do_configure () {
}

do_compile () {
	:
}

do_install () {
    install -d 644 ${D}${sysconfdir}/init.d
    install -d 644 ${D}${sysconfdir}/rcS.d
    install -m 0755 ${WORKDIR}/S99aesdsocket ${D}${sysconfdir}/init.d/S99aesdsocket
    ln -sf ../init.d/S99aesdsocket ${D}${sysconfdir}/rcS.d/S99aesdsocket
}


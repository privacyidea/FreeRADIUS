info:
	@echo "make clean        - remove all automatically created files"
	@echo "make debianzie    - prepare the debian build environment in DEBUILD"
	@echo "make builddeb     - build .deb file locally on ubuntu 14.04LTS!"
	@echo "make ppa-dev      - upload to launchpad development repo"
	@echo "make ppa          - upload to launchpad stable repo"
	
#VERSION=1.3~dev5
SHORT_VERSION=3.0~dev1
#SHORT_VERSION=2.10~dev7
VERSION_JESSIE=${SHORT_VERSION}
VERSION=${SHORT_VERSION}
LOCAL_SERIES=`lsb_release -a | grep Codename | cut -f2`
SRCDIRS=deploy
SRCFILES=copyright dictionary.netknights LICENSE Makefile privacyidea privacyidea_radius.pm  README.rst  rlm_perl.ini

SIGNING_KEY=53E66E1D2CABEFCDB1D3B83E106164552E8D8149

clean:
	rm -fr DEBUILD

BUILDDIR=DEBUILD/privacyidea-radius.org

debianize:
	make clean
	mkdir -p ${BUILDDIR}/debian
	cp -r ${SRCDIRS} ${SRCFILES} ${BUILDDIR} || true
	# remove the requirement for pyOpenSSL otherwise we get a breaking dependency for trusty
	cp copyright ${BUILDDIR}/debian/copyright
	cp copyright ${BUILDDIR}/debian/privacyidea-radius.copyright
	(cd DEBUILD; tar -zcf privacyidea-radius_${SHORT_VERSION}.orig.tar.gz --exclude=privacyidea-radius.org/debian privacyidea-radius.org)
	(cd DEBUILD; tar -zcf privacyidea-radius_${VERSION}.orig.tar.gz --exclude=privacyidea-radius.org/debian privacyidea-radius.org)
	(cd DEBUILD; tar -zcf privacyidea-radius_${VERSION_JESSIE}.orig.tar.gz --exclude=privacyidea-radius.org/debian privacyidea-radius.org)

builddeb-nosign:
	make debianize
	cp -r deploy/debian-ubuntu/* ${BUILDDIR}/debian/
	sed -e s/"trusty) trusty; urgency"/"$(LOCAL_SERIES)) $(LOCAL_SERIES); urgency"/g deploy/debian-ubuntu/changelog > ${BUILDDIR}/debian/changelog
	(cd ${BUILDDIR}; debuild -b -i -us -uc)

builddeb:
	make debianize
	################## Renew the changelog
	cp -r deploy/debian-ubuntu/* ${BUILDDIR}/debian/
	sed -e s/"trusty) trusty; urgency"/"$(LOCAL_SERIES)) $(LOCAL_SERIES); urgency"/g deploy/debian-ubuntu/changelog > ${BUILDDIR}/debian/changelog
	################# Build
	(cd ${BUILDDIR}; debuild --no-lintian)

lintian:
	(cd DEBUILD; lintian -i -I --show-overrides privacyidea-radius_*_amd64.changes)

ppa-dev:
	make debianize
	# trusty
	cp -r deploy/debian-ubuntu/* ${BUILDDIR}/debian/
	(cd ${BUILDDIR}; debuild -sa -S)
	# xenial
	sed -e s/"trusty) trusty; urgency"/"xenial) xenial; urgency"/g deploy/debian-ubuntu/changelog > ${BUILDDIR}/debian/changelog
	(cd ${BUILDDIR}; debuild -sa -S)
	# bionic
	sed -e s/"trusty) trusty; urgency"/"bionic) bionic; urgency"/g deploy/debian-ubuntu/changelog > ${BUILDDIR}/debian/changelog
	(cd ${BUILDDIR}; debuild -sa -S)
	dput ppa:privacyidea/privacyidea-dev DEBUILD/privacyidea-radius_${VERSION}*_source.changes

ppa:
	make debianize
	# trusty
	cp deploy/debian-ubuntu/changelog ${BUILDDIR}/debian/
	cp -r deploy/debian-ubuntu/* ${BUILDDIR}/debian/
	(cd ${BUILDDIR}; debuild -sa -S)
	# xenial
	sed -e s/"trusty) trusty; urgency"/"xenial) xenial; urgency"/g deploy/debian-ubuntu/changelog > ${BUILDDIR}/debian/changelog
	(cd ${BUILDDIR}; debuild -sa -S)
	dput ppa:privacyidea/privacyidea DEBUILD/privacyidea-radius_${VERSION}*_source.changes

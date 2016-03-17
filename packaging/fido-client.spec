
Name:       fido-client
Summary:    Tizen FIDO Client
Version:    0.0.1
Release:    1
Group:      Social & Content/API
License:    Apache-2.0
Source0:    fido-client-%{version}.tar.gz
Source1:    org.tizen.fido.service
Source2:    org.tizen.fido.conf
Source3:    fido.service

Source4:    org.tizen.dummyasm.service
Source5:    org.tizen.dummyasm.conf

BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(capi-base-common)
BuildRequires:	pkgconfig(glib-2.0) >= 2.26
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  pkgconfig(cynara-client)
BuildRequires:  pkgconfig(cynara-session)
BuildRequires:  pkgconfig(cynara-creds-gdbus)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(json-glib-1.0)
##BuildRequires:  pkgconfig(capi-appfw-application)
BuildRequires:  pkgconfig(capi-appfw-app-manager)
BuildRequires:  pkgconfig(libsoup-2.4)
BuildRequires:  pkgconfig(elementary)
BuildRequires:  pkgconfig(efl-extension)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  python-xml

Requires(post): /sbin/ldconfig
Requires(post): /usr/bin/sqlite3
Requires(postun): /sbin/ldconfig

%description
Tizen FIDO Client provides FIDO UAF spec compliant APIs.

%package devel
Summary:    Dev files for %{name}
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
%description devel
Development files for %{name}

%define _pkg_dir                %{TZ_SYS_RO_APP}/org.tizen.fidosvcui
%define _bin_dir                %{_pkg_dir}/bin
%define _lib_dir                %{_pkg_dir}/lib
%define _res_dir                %{_pkg_dir}/res
%define _locale_dir             %{_res_dir}/locale
%define _manifest_dir           %{TZ_SYS_RO_PACKAGES}
%define _icon_dir               %{TZ_SYS_RO_ICONS}/default/small

%prep
%setup -q

%build
%if 0%{?sec_build_binary_debug_enable}
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif

export CFLAGS="${CFLAGS} -fPIC -fvisibility=hidden"

cmake . \
-DCMAKE_INSTALL_PREFIX=%{_prefix} \
-DLIBDIR=%{_libdir} \
-DINCLUDEDIR=%{_includedir} \
-DBIN_DIR=%{_bin_dir} \
-DRES_DIR=%{_res_dir} \
-DLOCALE_DIR=%{_locale_dir} \
-DMANIFEST_DIR=%{_manifest_dir} \
-DICON_DIR=%{_icon_dir}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}

%make_install

mkdir -p %{buildroot}/usr/share/dbus-1/system-services
install -m 0644 %SOURCE1 %{buildroot}/usr/share/dbus-1/system-services/org.tizen.fido.service

mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d
install -m 0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/dbus-1/system.d/

mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
install -m 644 %SOURCE3 %{buildroot}%{_unitdir}/fido.service
%install_service multi-user.target.wants fido.service

mkdir -p %{buildroot}/usr/share/dbus-1/system-services
install -m 0644 %SOURCE4 %{buildroot}/usr/share/dbus-1/system-services/org.tizen.dummyasm.service

mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d
install -m 0644 %{SOURCE5} %{buildroot}%{_sysconfdir}/dbus-1/system.d/

mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
install -m 644 %SOURCE4 %{buildroot}%{_unitdir}/org.tizen.dummyasm.service
%install_service multi-user.target.wants org.tizen.dummyasm.service

install -m 0644  test/Dummy_ASM_DBUS/dummy_asm.json %{buildroot}%{_libdir}/fido/asm/dummy_asm.json

%make_install
mkdir -p %{buildroot}%{_libdir}

%post
chsmack -a '_' %{_libdir}/fido/
chsmack -a '_' %{_libdir}/fido/asm/
/sbin/ldconfig

%postun
/sbin/ldconfig

%files
%{_libdir}/*.so.*
%manifest fido.manifest
%config %{_sysconfdir}/dbus-1/system.d/org.tizen.fido.conf
%{_bindir}/fido-service
%attr(0644,root,root) %{_unitdir}/fido.service
%attr(0644,root,root) %{_unitdir}/multi-user.target.wants/fido.service
%attr(0644,root,root) /usr/share/dbus-1/system-services/org.tizen.fido.service

%files devel
%defattr(-,root,root,-)
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
%{_includedir}/*.h
/opt/usr/devel/fido/tc/*


#################################################################################
# FIDO Service UI

%package -n org.tizen.fidosvcui
Summary:    FIDO Service UI
Group:       Social & Content/API

BuildRequires: cmake 
BuildRequires: pkgconfig(capi-appfw-application)
BuildRequires: pkgconfig(capi-system-system-settings)
BuildRequires: pkgconfig(elementary)
BuildRequires: pkgconfig(efl-extension)
BuildRequires: pkgconfig(dlog)
BuildRequires:  pkgconfig(bundle)
BuildRequires: pkgconfig(json-glib-1.0)
BuildRequires:	pkgconfig(glib-2.0) >= 2.26
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(libtzplatform-config)
Requires: fido-client

%description -n org.tizen.fidosvcui
FIDO Service UI provides Authenticator selection UI.

%files -n org.tizen.fidosvcui
%defattr(-,root,root,-)
%manifest org.tizen.fidosvcui.manifest
%{TZ_SYS_RO_APP}/org.tizen.fidosvcui/bin/*
%{TZ_SYS_SHARE}/packages/org.tizen.fidosvcui.xml
%{TZ_SYS_SHARE}/icons/default/small/org.tizen.fidosvcui.png

#################################################################################
# FIDO Dummy ASM
%package -n dummyasm
Summary:    FIDO Dummy ASM (Internal Dev)
Group:      Social & Content/API

BuildRequires: cmake
BuildRequires: pkgconfig(capi-appfw-application)
BuildRequires: pkgconfig(capi-system-system-settings)
BuildRequires: pkgconfig(elementary)
BuildRequires: pkgconfig(efl-extension)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(json-glib-1.0)
BuildRequires: pkgconfig(glib-2.0) >= 2.26
BuildRequires: pkgconfig(gio-unix-2.0)
BuildRequires: pkgconfig(libtzplatform-config)
Requires: fido-client

%description -n dummyasm
This is a dummy ASM for testing FIDO client.

%files -n dummyasm
%manifest dummyasm.manifest
%config %{_sysconfdir}/dbus-1/system.d/org.tizen.dummyasm.conf
%{_bindir}/dummyasm-service
%attr(0644,root,root) %{_unitdir}/org.tizen.dummyasm.service
%attr(0644,root,root) %{_unitdir}/multi-user.target.wants/org.tizen.dummyasm.service
%attr(0644,root,root) /usr/share/dbus-1/system-services/org.tizen.dummyasm.service
%{_libdir}/fido/asm/dummy_asm.json

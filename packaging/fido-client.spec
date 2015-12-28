
Name:       fido-client
Summary:    Tizen FIDO Client
Version:    0.0.1
Release:    1
Group:      Social & Content/API
License:    Apache-2.0
Source0:    fido-client-%{version}.tar.gz
Source1:    org.tizen.fido.service
Source2:    org.tizen.fido.conf
Source3:    org.tizen.fido.service

Source4:    org.tizen.dummyasm.service
Source5:    org.tizen.dummyasm.conf

BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(capi-base-common)
BuildRequires:	pkgconfig(glib-2.0) >= 2.26
BuildRequires:  pkgconfig(gio-unix-2.0)
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
Tizen FIDO Client

%package devel
Summary:    Development files for %{name}
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
%description devel
Development files for %{name}

%prep
%setup -q

%build
#export   CFLAGS+=" -Wextra -Wcast-align -Wcast-qual -Wshadow -Wwrite-strings -Wswitch-default"
#export CXXFLAGS+=" -Wextra -Wcast-align -Wcast-qual -Wshadow -Wwrite-strings -Wswitch-default -Wnon-virtual-dtor -Wno-c++0x-compat"
#export   CFLAGS+=" -Wno-unused-parameter -Wno-empty-body"
#export CXXFLAGS+=" -Wno-unused-parameter -Wno-empty-body"

#export   CFLAGS+=" -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-strict-aliasing -fno-unroll-loops -fsigned-char -fstrict-overflow -fno-common"
#export CXXFLAGS+=" -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-strict-aliasing -fno-unroll-loops -fsigned-char -fstrict-overflow"

export CFLAGS="${CFLAGS} -fPIC -fvisibility=hidden"
cmake . -DCMAKE_INSTALL_PREFIX=/usr

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp %{_builddir}/%{name}-%{version}/LICENSE.Apache-2.0  %{buildroot}/usr/share/license/%{name}
%make_install

mkdir -p %{buildroot}/usr/share/dbus-1/system-services
install -m 0644 %SOURCE1 %{buildroot}/usr/share/dbus-1/system-services/org.tizen.fido.service

mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d
install -m 0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/dbus-1/system.d/

mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
install -m 644 %SOURCE3 %{buildroot}%{_unitdir}/org.tizen.fido.service
%install_service multi-user.target.wants org.tizen.fido.service


mkdir -p %{buildroot}/usr/share/dbus-1/system-services
install -m 0644 %SOURCE4 %{buildroot}/usr/share/dbus-1/system-services/org.tizen.dummyasm.service

mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d
install -m 0644 %{SOURCE5} %{buildroot}%{_sysconfdir}/dbus-1/system.d/

mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
install -m 644 %SOURCE4 %{buildroot}%{_unitdir}/org.tizen.dummyasm.service
%install_service multi-user.target.wants org.tizen.dummyasm.service

install -m 0644  test/Dummy_ASM_DBUS/dummy_asm.json %{buildroot}%{_libdir}/fido/asm/dummy_asm.json

##rm -rf %{buildroot}/usr/lib/fido

%post
mkdir -p /usr/lib/fido/asm/
chsmack -a '_' /usr/lib/fido/
chsmack -a '_' /usr/lib/fido/asm/
/sbin/ldconfig

%postun
/sbin/ldconfig

%files
/usr/share/license/%{name}
%{_libdir}/*.so.*
%manifest fido.manifest
%config %{_sysconfdir}/dbus-1/system.d/org.tizen.fido.conf
%{_bindir}/fido-service
%attr(0644,root,root) %{_unitdir}/org.tizen.fido.service
%attr(0644,root,root) %{_unitdir}/multi-user.target.wants/org.tizen.fido.service
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
Group:      Account
#Requires:   %{name} = %{version}-%{release}

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
Requires: fido-client

%description -n org.tizen.fidosvcui
FIDO Service UI

%files -n org.tizen.fidosvcui
%defattr(-,root,root,-)
/usr/share/license/%{name}
%manifest org.tizen.fidosvcui.manifest
/usr/apps/org.tizen.fidosvcui/bin/*
##/usr/apps/org.tizen.fidosvcui/res/*
/usr/share/packages/org.tizen.fidosvcui.xml
/usr/share/icons/default/small/org.tizen.fidosvcui.png

#################################################################################
# FIDO Dummy ASM
%package -n dummyasm
Summary:    FIDO Dummy ASM (Internal Dev)
Group:      Account/Testing

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
This is a dummy ASM.

%files -n dummyasm
%manifest dummyasm.manifest
%config %{_sysconfdir}/dbus-1/system.d/org.tizen.dummyasm.conf
%{_bindir}/dummyasm-service
%attr(0644,root,root) %{_unitdir}/org.tizen.dummyasm.service
%attr(0644,root,root) %{_unitdir}/multi-user.target.wants/org.tizen.dummyasm.service
%attr(0644,root,root) /usr/share/dbus-1/system-services/org.tizen.dummyasm.service
%{_libdir}/fido/asm/dummy_asm.json

#################################################################################
# Fido Sample App

%package -n org.tizen.FidoSample
Summary:    Fido Sample App (Internal Dev)
Group:      Account/Testing
#Requires:   %{name} = %{version}-%{release}

BuildRequires: cmake 
BuildRequires: pkgconfig(capi-appfw-application)
BuildRequires: pkgconfig(capi-system-system-settings)
BuildRequires: pkgconfig(elementary)
BuildRequires: pkgconfig(efl-extension)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(json-glib-1.0)
BuildRequires: pkgconfig(glib-2.0) >= 2.26
BuildRequires: pkgconfig(gio-unix-2.0)
Requires: fido-client

%description -n org.tizen.FidoSample
This is a program to test the Fido service internally.

%files -n org.tizen.FidoSample
%defattr(-,root,root,-)
/usr/share/license/%{name}
%manifest org.tizen.FidoSample.manifest
/opt/usr/apps/org.tizen.FidoSample/bin/*
/opt/usr/apps/org.tizen.FidoSample/res/*
/opt/usr/apps/org.tizen.FidoSample/shared/res/*
/opt/share/packages/org.tizen.FidoSample.xml
##/opt/share/icons/default/small/org.tizen.FidoSample.png

Name:       secure-storage
Summary:    Secure storage
Version:    0.12.9
Release:    4
Group:      System/Security
License:    Apache 2.0
Source0:    secure-storage-%{version}.tar.gz
Source1:    secure-storage.service
Source1001:	libss-client.manifest
Source1002:	libss-client-devel.manifest
Source1003:	ss-server.manifest
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(dlog)
#BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  cmake

%description
Secure storage package

%package -n libss-client
Summary:    Secure storage  (client)
Group:      Development/Libraries
Provides:   libss-client.so

%description -n libss-client
Secure storage package (client)

%package -n libss-client-devel
Summary:    Secure storage  (client-devel)
Group:      Development/Libraries
Requires:   libss-client = %{version}-%{release}

%description -n libss-client-devel
Secure storage package (client-devel)

%package -n ss-server
Summary:    Secure storage  (ss-server)
Group:      Development/Libraries
Requires(preun): /usr/bin/systemctl
Requires(post):  /usr/bin/systemctl
Requires(postun): /usr/bin/systemctl
Requires:   systemd
Requires:   libss-client = %{version}-%{release}

%description -n ss-server
Secure storage package (ss-server)

%prep
%setup -q
cp %{SOURCE1001} %{SOURCE1002} %{SOURCE1003} .


%build
%cmake .


make %{?jobs:-j%jobs}

%install
%make_install

mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/multi-user.target.wants
install -m 0644 %{SOURCE1} %{buildroot}%{_prefix}/lib/systemd/system/secure-storage.service
ln -s ../secure-storage.service %{buildroot}%{_prefix}/lib/systemd/system/multi-user.target.wants/secure-storage.service

mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc3.d
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc5.d
ln -s ../init.d/ss-serverd %{buildroot}%{_sysconfdir}/rc.d/rc3.d/S40ss-server
ln -s ../init.d/ss-serverd %{buildroot}%{_sysconfdir}/rc.d/rc5.d/S40ss-server

mkdir -p %{buildroot}/usr/share/license
cp LICENSE.APLv2 %{buildroot}/usr/share/license/ss-server
cp LICENSE.APLv2 %{buildroot}/usr/share/license/libss-client

%preun -n ss-server
if [ $1 == 0 ]; then
    systemctl stop secure-storage.service
fi

%post -n ss-server
systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl restart secure-storage.service
fi

%postun -n ss-server
systemctl daemon-reload

%post -n libss-client -p /sbin/ldconfig

%postun -n libss-client -p /sbin/ldconfig

%files -n ss-server
%manifest ss-server.manifest
%defattr(-,root,root,-)
%attr(0755,root,root) %{_sysconfdir}/rc.d/init.d/ss-serverd
%{_sysconfdir}/rc.d/rc3.d/S40ss-server
%{_sysconfdir}/rc.d/rc5.d/S40ss-server
%{_bindir}/ss-server
%{_prefix}/lib/systemd/system/secure-storage.service
%{_prefix}/lib/systemd/system/multi-user.target.wants/secure-storage.service
%{_datadir}/secure-storage/config
/usr/share/license/ss-server

%files -n libss-client
%manifest libss-client.manifest
%defattr(-,root,root)
%{_libdir}/libss-client.so.*
/usr/share/license/libss-client

%files -n libss-client-devel
%manifest libss-client-devel.manifest
%defattr(-,root,root,-)
%{_includedir}/ss_manager.h
%{_libdir}/pkgconfig/secure-storage.pc
%{_libdir}/libss-client.so


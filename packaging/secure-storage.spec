Name:       secure-storage
Summary:    Secure storage
Version:    0.12.9
Release:    4
Group:      System/Security
License:    Apache 2.0
Source0:    secure-storage-%{version}.tar.gz
Source1001:	libss-client.manifest
Source1002:	libss-client-devel.manifest
Source1003:	ss-server.manifest
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  cmake
BuildRequires:  pkgconfig(dukgenerator)

%description
Secure storage package

%package -n libss-client
Summary:    Secure storage  (client)
Group:      Development/Libraries
Provides:   libss-client.so
Requires:   dukgenerator

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
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/sockets.target.wants
ln -s ../secure-storage.service %{buildroot}%{_prefix}/lib/systemd/system/multi-user.target.wants/secure-storage.service
ln -s ../secure-storage.socket %{buildroot}%{_prefix}/lib/systemd/system/sockets.target.wants/secure-storage.socket

mkdir -p %{buildroot}/usr/share/license
cp LICENSE.APLv2 %{buildroot}/usr/share/license/ss-server
cp LICENSE.APLv2 %{buildroot}/usr/share/license/libss-client

%preun -n ss-server
if [ $1 == 0 ]; then
    systemctl stop secure-storage.service
    systemctl disable secure-storage.service -q
fi

%post -n ss-server
systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl enable secure-storage.service -q
    systemctl restart secure-storage.service
fi

%postun -n ss-server
systemctl daemon-reload

%post -n libss-client -p /sbin/ldconfig

%postun -n libss-client -p /sbin/ldconfig

%files -n ss-server
%manifest ss-server.manifest
%defattr(-,root,root,-)
%{_bindir}/ss-server
%{_prefix}/lib/systemd/system/secure-storage.service
%{_prefix}/lib/systemd/system/multi-user.target.wants/secure-storage.service
%{_prefix}/lib/systemd/system/secure-storage.socket
%{_prefix}/lib/systemd/system/sockets.target.wants/secure-storage.socket
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


Name:       secure-storage
Summary:    Secure storage
Version:    0.12.7
Release:    1
Group:      System/Security
License:    Apache 2.0
Source0:    secure-storage-%{version}.tar.gz
Source1:    secure-storage.service
Source1001: packaging/secure-storage.manifest
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  cmake

%description
Secure storage package

%package -n libss-client
Summary:    Secure storage  (client)
Group:      Development/Libraries
Provides:   libss-client.so
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

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


%build
cp %{SOURCE1001} .
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}


make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
install -m 0644 %{SOURCE1} %{buildroot}%{_libdir}/systemd/system/secure-storage.service
ln -s ../secure-storage.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/secure-storage.service

mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc3.d
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc5.d
ln -s ../init.d/ss-serverd %{buildroot}%{_sysconfdir}/rc.d/rc3.d/S40ss-server
ln -s ../init.d/ss-serverd %{buildroot}%{_sysconfdir}/rc.d/rc5.d/S40ss-server

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
%manifest secure-storage.manifest
%attr(0755,root,root) %{_sysconfdir}/rc.d/init.d/ss-serverd
%{_sysconfdir}/rc.d/rc3.d/S40ss-server
%{_sysconfdir}/rc.d/rc5.d/S40ss-server
%{_bindir}/ss-server
%{_libdir}/systemd/system/secure-storage.service
%{_libdir}/systemd/system/multi-user.target.wants/secure-storage.service
%{_datadir}/secure-storage/config

%files -n libss-client
%manifest secure-storage.manifest
%{_libdir}/libss-client.so.*

%files -n libss-client-devel
%manifest secure-storage.manifest
%defattr(-,root,root,-)
%{_includedir}/ss_manager.h
%{_libdir}/pkgconfig/secure-storage.pc
%{_libdir}/libss-client.so


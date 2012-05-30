#sbs-git:slp/pkgs/s/secure-storage secure-storage 0.12.7 b703988ab31e25e5cbb23de33d39b411f6052e1f
Name:       secure-storage
Summary:    Secure storage
Version: 0.12.7
Release:    1
Group:      System/Security
License:    Apache 2.0
Source0:    secure-storage-%{version}.tar.gz
Source1001: packaging/secure-storage.manifest 
Requires(post): /sbin/service
Requires(post): /sbin/chkconfig
Requires(postun): /sbin/service
Requires(postun): /sbin/chkconfig
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


%post -n ss-server
mkdir -p /etc/rc.d/rc3.d
mkdir -p /etc/rc.d/rc5.d
ln -s /etc/rc.d/init.d/ss-serverd /etc/rc.d/rc3.d/S40ss-server
ln -s /etc/rc.d/init.d/ss-serverd /etc/rc.d/rc5.d/S40ss-server

%postun -n ss-server
rm -f /etc/rc.d/rc3.d/S40ss-server
rm -f /etc/rc.d/rc5.d/S40ss-server

%post -n libss-client -p /sbin/ldconfig

%postun -n libss-client -p /sbin/ldconfig

%files -n ss-server
%manifest secure-storage.manifest
%defattr(-,root,root,-)
/usr/share/secure-storage/config
/etc/rc.d/init.d/ss-serverd
/usr/bin/ss-server

%files -n libss-client
%manifest secure-storage.manifest
%defattr(-,root,root)
/usr/lib/libss-client.so.*

%files -n libss-client-devel
%manifest secure-storage.manifest
%defattr(-,root,root,-)
/usr/include/ss_manager.h
/usr/lib/pkgconfig/secure-storage.pc
/usr/lib/libss-client.so


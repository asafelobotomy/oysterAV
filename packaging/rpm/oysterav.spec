# oysterAV RPM packaging for Fedora COPR / local rpmbuild.
# Community GitHub .rpm artifacts remain fpm-built; this .spec is the COPR path.

Name:           oysterav
Version:        0.2.2
Release:        1%{?dist}
Summary:        Linux security orchestrator (oyst-cli + GTK4 GUI)
License:        GPL-3.0-or-later
URL:            https://github.com/asafelobotomy/oysterAV
Source0:        https://github.com/asafelobotomy/oysterAV/archive/refs/tags/v%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  python3-build
BuildRequires:  python3-installer
BuildRequires:  python3-wheel
BuildRequires:  python3-hatchling
Requires:       python3
Requires:       python3-click
Requires:       python3-pydantic
Requires:       python3-defusedxml
Requires:       python3-gobject
Requires:       gtk4
Requires:       libadwaita
Requires:       polkit

%description
oysterAV orchestrates Linux security tools (ClamAV, rkhunter, Lynis, and more)
via oyst-cli and a thin GTK4 GUI. This package installs system paths under /usr
including the Polkit privileged helper.

Optional host tools (clamav, rkhunter, …) are not hard Requires — install them
for Lite/Full mode as needed.

%prep
%autosetup -n oysterAV-%{version}

%build
%{_bindir}/python3 -m build --wheel --no-isolation

%install
%{_bindir}/python3 -m installer --destdir=%{buildroot} dist/*.whl

install -d %{buildroot}/usr/lib/oysterav
cat > %{buildroot}/usr/lib/oysterav/oyst-helper <<'EOF'
#!/usr/bin/env python3
from oyst_core.privileged.oyst_helper import main
main()
EOF
chmod 755 %{buildroot}/usr/lib/oysterav/oyst-helper
install -d %{buildroot}%{_bindir}
ln -sf ../lib/oysterav/oyst-helper %{buildroot}%{_bindir}/oyst-helper

install -Dm644 packaging/oysterav/io.github.asafelobotomy.OysterAV.desktop \
  %{buildroot}%{_datadir}/applications/io.github.asafelobotomy.OysterAV.desktop
install -Dm644 packaging/oysterav/flatpak/io.github.asafelobotomy.OysterAV.metainfo.xml \
  %{buildroot}%{_metainfodir}/io.github.asafelobotomy.OysterAV.metainfo.xml
install -Dm644 packaging/polkit/io.github.asafelobotomy.policy \
  %{buildroot}%{_datadir}/polkit-1/actions/io.github.asafelobotomy.policy

for size in 16 32 48 128 256 512; do
  install -Dm644 branding/hicolor/${size}x${size}/apps/oysterav.png \
    %{buildroot}%{_datadir}/icons/hicolor/${size}x${size}/apps/oysterav.png
done

%files
%license LICENSE
%doc README.md
%{python3_sitelib}/oyst_core*
%{python3_sitelib}/oyst_cli*
%{python3_sitelib}/oysterav*
%{_bindir}/oyst-cli
%{_bindir}/oysterav
%{_bindir}/oyst-helper
/usr/lib/oysterav/oyst-helper
%{_datadir}/applications/io.github.asafelobotomy.OysterAV.desktop
%{_metainfodir}/io.github.asafelobotomy.OysterAV.metainfo.xml
%{_datadir}/polkit-1/actions/io.github.asafelobotomy.policy
%{_datadir}/icons/hicolor/*/apps/oysterav.png

%changelog
* Mon Jul 27 2026 oysterAV contributors <noreply@users.noreply.github.com> - 0.2.2-1
- Packaging harden: Python Depends alignment and Flathub multi-arch notes

* Sun Jul 27 2026 oysterAV contributors <noreply@users.noreply.github.com> - 0.2.1-1
- Initial COPR-oriented packaging

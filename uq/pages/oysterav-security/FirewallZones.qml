// The firewalld half of the Firewall tab: pick a zone, see what is open in it, open or close a port or a service.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.uq.settings
import "firewall.js" as Fw

SettingsCard {
    id: card

    /// The Firewall tab (FirewallTab.qml): its state, and the page it writes through.
    property var owner

    title: "Zones"
    iconName: "network-workgroup"
    help: "firewalld sorts networks into zones; each zone lets in only the services and ports open in it."
    visible: !!card.owner && card.owner.firewalld
    wide: true
    Layout.fillWidth: true

    UqLabel {
        visible: card.owner.firewalld && !card.owner.fw.on
        text: "Turn the firewall on to see and change its zones."
        opacity: 0.7
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    SettingRow {
        settingId: "firewall-rules"
        label: "Zone"
        highlight: card.owner.host ? card.owner.host.highlight : ""
        visible: card.owner.zone !== null
        Layout.fillWidth: true

        UqComboBox {
            objectName: "fw-zone"
            model: card.owner.firewalld ? card.owner.fw.zones.map(z => z.label) : []
            currentIndex: card.owner.firewalld && card.owner.zone ? card.owner.fw.zones.indexOf(card.owner.zone) : -1
            onActivated: index => card.owner.zoneName = card.owner.fw.zones[index].name
        }
    }
    UqLabel {
        visible: card.owner.zone !== null
        text: card.owner.zone === null ? "" : (card.owner.zone.interfaces.length > 0 ? "Used by " + card.owner.zone.interfaces.join(", ") : "No network uses this zone")
        opacity: 0.7
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Repeater {
        model: card.owner.zone === null ? [] : card.owner.zone.services.map(s => ({ kind: "service", value: s })).concat(card.owner.zone.ports.map(p => ({ kind: "port", value: p })))

        SettingRow {
            id: open

            required property var modelData
            required property int index

            label: (open.modelData.kind === "service" ? "Service " : "Port ") + open.modelData.value
            Layout.fillWidth: true

            QQC2.Button {
                objectName: "fw-close-" + open.index
                text: "Close"
                icon.name: "list-remove"
                visible: open.modelData.kind === "service" || /^[0-9]{1,5}\/(tcp|udp)$/.test(open.modelData.value)
                enabled: card.owner.usable
                onClicked: card.owner.host.write("fw:zone", open.modelData.kind === "service" ? "fw-zone-service" : "fw-zone-port", ["remove", card.owner.zone.name, open.modelData.value], () => card.owner.after(), open.modelData.value + " is closed.")
            }
        }
    }
    UqLabel {
        visible: card.owner.zone !== null && card.owner.zone.services.length + card.owner.zone.ports.length === 0
        text: "Nothing is open in this zone."
        opacity: 0.7
    }
    SettingRow {
        label: "Open a port"
        visible: card.owner.zone !== null
        enabled: card.owner.usable
        Layout.fillWidth: true

        QQC2.TextField {
            id: zonePort
            objectName: "fw-zone-port"
            placeholderText: "8080"
            implicitWidth: 100
        }
        UqComboBox {
            id: zoneProto
            model: Fw.FW_PROTOS.map(p => Fw.FW_PROTO_LABELS[p])
        }
        QQC2.Button {
            text: "Open"
            icon.name: "list-add"
            onClicked: card.owner.openInZone("port", Fw.fwPortSpec(zonePort.text, Fw.FW_PROTOS[Math.max(0, zoneProto.currentIndex)]))
        }
    }
    SettingRow {
        label: "Open a service"
        visible: card.owner.zone !== null
        enabled: card.owner.usable
        Layout.fillWidth: true

        QQC2.TextField {
            id: zoneService
            objectName: "fw-zone-service"
            placeholderText: "ssh, http, kdeconnect"
            implicitWidth: 180
        }
        QQC2.Button {
            text: "Open"
            icon.name: "list-add"
            onClicked: card.owner.openInZone("service", zoneService.text.trim())
        }
    }
    Outcome {
        host: card.owner.host
        noteKey: "fw:zone"
        bar: true
        Layout.fillWidth: true
    }
}

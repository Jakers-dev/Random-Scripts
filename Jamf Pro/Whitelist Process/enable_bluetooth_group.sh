#!/bin/bash

# Will enable bluetooth for all members of the group Id in parameter 4

IDs=( $( curl -X GET -H "Accept: application/xml" -ksH 'authorization: Basic base64encoded_username:pass' https://instance.jamfcloud.com/JSSResource/mobiledevicegroups/id/$4 | /usr/bin/perl -lne 'BEGIN{undef $/} while (/<mobile_device><id>(.*?)<\/id>/sg){print $1}' ) )

for i in ${IDs[@]}; do
    /usr/bin/curl -X POST https://instance.jamfcloud.com/JSSResource/mobiledevicecommands/command -ksH 'authorization: Basic base64encoded_username:pass' -H 'content-type: application/xml' -d "<mobile_device_command><general><command>SettingsEnableBluetooth</command></general><mobile_devices><mobile_device><id>$i</id></mobile_device></mobile_devices></mobile_device_command>" > /dev/null
done
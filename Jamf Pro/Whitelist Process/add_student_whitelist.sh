#!/bin/bash


# Make changes to mobile device app deployment. See api

#Computer policy to run script on daily basis with client restrictions to limit days

curl -X PUT -H "Content-Type: application/xml" -ksH 'authorization: Basic base64encoded_username:pass' -d "<configuration_profile><scope><mobile_device_groups><mobile_device_group><id>$5</id><name>$6</name></mobile_device_group></mobile_device_groups><exclusions><jss_user_groups><user_group><id>3</id><name>Sick Students</name></user_group></jss_user_groups></exclusions></scope></configuration_profile>" "https://instance.jamfcloud.com/JSSResource/mobiledeviceconfigurationprofiles/id/$4"


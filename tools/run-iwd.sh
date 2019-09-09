#!/bin/bash

systemd-run \
	--pty --wait --collect \
	--unit=iwd.service \
	--service-type=dbus \
	--property=BusName=net.connman.iwd \
	--property=NotifyAccess=main \
	--property=LimitNPROC=1 \
	--property=Restart=on-failure \
	--property=PrivateTmp=true \
	--property=NoNewPrivileges=true \
	--property=DevicePolicy=closed \
	--property=DeviceAllow=/dev/rfkill\ rw \
	--property=ProtectHome=yes \
	--property=ProtectSystem=strict \
	--property=ProtectControlGroups=yes \
	--property=ProtectKernelModules=yes \
	--property=ConfigurationDirectory=iwd \
	--property=StateDirectory=iwd \
	--property=StateDirectoryMode=0700 \
	./src/iwd $*

#!/bin/bash
cd /usr/local/jenkins-service
curl -sO https://testautomation.ocm.sunet.dev/jnlpJars/agent.jar
java -jar agent.jar -url https://testautomation.ocm.sunet.dev/ -secret @secret-file -name $(hostname) -workDir "/var/lib/jenkins"
exit 0
